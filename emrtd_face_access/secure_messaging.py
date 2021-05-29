#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module has functions for BAC and Secure Messaging (SM)"""

import hashlib

from Crypto.Cipher import DES, DES3, AES
from Crypto.Hash import CMAC
from Crypto.Util.strxor import strxor

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_node_next,
    asn1_get_value,
)

from emrtd_face_access.apdu import APDU
from emrtd_face_access.asn1 import asn1_len
from emrtd_face_access.byte_operations import padding_method_2, remove_padding
from emrtd_face_access.secure_messaging_object import SMObject


def compute_key(key_seed: bytes, key_type: str, alg: str) -> bytes:
    """Compute enc and mac keys from key_seed.

    key_seed -- 16 bytes
    key_type -- type of key to be created (choices "enc", "mac", "pace")
    alg -- which algorithm to create keys for (choices "3DES", "AES-128", "AES-192", "AES-256")
    :returns: 3DES or AES key
    """
    if key_type == "enc":
        c = b"\x00\x00\x00\x01"
    elif key_type == "mac":
        c = b"\x00\x00\x00\x02"
    elif key_type == "pace":
        c = b"\x00\x00\x00\x03"
    else:
        raise ValueError('key_type must either be "enc" or "mac"')
    D = key_seed + c

    if alg == "3DES":
        hash_of_D = hashlib.sha1(D).digest()
        key_a = hash_of_D[:8]
        key_b = hash_of_D[8:16]
        return DES3.adjust_key_parity(key_a + key_b)  # set parity bits
    if alg == "AES-128":
        return hashlib.sha1(D).digest()[:16]
    if alg == "AES-192":
        return hashlib.sha256(D).digest()[:24]
    if alg == "AES-256":
        return hashlib.sha256(D).digest()
    else:
        raise ValueError("[-] Unknown encryption algorithm!")


def compute_mac(key: bytes, data: bytes, alg: str) -> bytes:
    """
    Calculate message authentication code (mac) of data using key
    according to IEC_9797-1 MAC algorithm 3
    https://en.wikipedia.org/wiki/ISO/IEC_9797-1 MAC algorithm 3\n
    http://www.devinvenable.com/mediawiki/index.php/ISO_9797_algorithm_3

    key -- DES key to compute the mac with, 16 bytes
    data -- data to calculate the mac of
    alg -- which algorithm to use for mac (choices "DES", "AES-CMAC")
    :returns: mac of data
    """

    if alg == "DES":
        m_cipher1 = DES.new(key[:8], DES.MODE_ECB)
        m_cipher2 = DES.new(key[-8:], DES.MODE_ECB)

        h = m_cipher1.encrypt(data[:8])
        for i in range(1, len(data) // 8):
            h = m_cipher1.encrypt(strxor(h, data[8 * i : 8 * (i + 1)]))
        mac_x = m_cipher1.encrypt(m_cipher2.decrypt(h))
        return mac_x
    elif alg == "AES-CMAC":
        mac_x = CMAC.new(key, ciphermod=AES, msg=data, mac_len=8).digest()
        return mac_x
    else:
        raise ValueError("[-] Unsupported MAC algorithm")


def secure_messaging(sm_object: SMObject, apdu: APDU) -> bytes:
    """
    Sends an APDU using secure messaging.
    """
    if (
        sm_object.enc_alg is None
        or sm_object.mac_alg is None
        or sm_object.pad_len == 0
        or sm_object.ks_enc is None
        or sm_object.ks_mac is None
        or sm_object.ssc is None
    ):
        return apdu.get_command_header() + (apdu.Lc or b"") + (apdu.cdata or b"") + (apdu.Le or b"")

    apdu.cla = bytes([apdu.cla[0] | 0x0C])

    sm_object.increment_ssc()

    payload = b""
    if apdu.cdata is not None:
        data = padding_method_2(apdu.cdata, sm_object.pad_len)
        if sm_object.enc_alg == "3DES":
            des_cipher = DES3.new(sm_object.ks_enc, DES3.MODE_CBC, iv=bytes([0] * 8))
            encrypted_data = des_cipher.encrypt(data)
        elif sm_object.enc_alg == "AES":
            ssc_enc = AES.new(sm_object.ks_enc, AES.MODE_ECB).encrypt(sm_object.ssc)
            aes_cipher = AES.new(sm_object.ks_enc, AES.MODE_CBC, iv=ssc_enc)
            encrypted_data = aes_cipher.encrypt(data)

        if int.from_bytes(apdu.ins, byteorder="big") % 2 == 0:
            # For a command with even INS, any command data is encrypted
            # and capsulated in a Tag 87 with padding indicator (01).
            do87 = b"\x87" + asn1_len(b"\x01" + encrypted_data) + b"\x01" + encrypted_data
            payload += do87
        else:
            # For a command with odd INS, any command data is encrypted
            # and capsulated in a Tag 85 without padding indicator.
            do85 = b"\x85" + asn1_len(encrypted_data) + encrypted_data
            payload += do85

    if apdu.Le is not None:
        # Commands with response (Le field not empty)
        # have a protected Le-field (Tag 97) in the command data.
        do97 = b"\x97" + asn1_len(apdu.Le) + apdu.Le
        payload += do97

    padded_header = padding_method_2(apdu.get_command_header(), sm_object.pad_len)
    n = padding_method_2(sm_object.ssc + padded_header + payload, sm_object.pad_len)
    cc = compute_mac(sm_object.ks_mac, n, sm_object.mac_alg)

    do8e = b"\x8E" + asn1_len(cc) + cc

    payload += do8e
    protected_apdu = apdu.get_command_header() + bytes([len(payload)]) + payload + b"\x00"

    return protected_apdu


class ReplyAPDUError(Exception):
    """Exception to be raised if the MAC doesn't match"""


def process_rapdu(sm_object: SMObject, rapdu: bytes) -> bytes:
    """
    Verify the MAC of the received APDU and return the decrypted data if it exists

    sm_object -- Necessary secure messaging object (Encryption session key etc.)
    rapdu -- Received Reply APDU
    :returns: decrypted_data or None
    """
    if (
        sm_object.enc_alg is None
        or sm_object.mac_alg is None
        or sm_object.pad_len == 0
        or sm_object.ks_enc is None
        or sm_object.ks_mac is None
        or sm_object.ssc is None
    ):
        return rapdu

    sm_object.increment_ssc()

    encrypted_data, decrypted_data = b"", b""
    do85, do87, do99 = None, None, None
    i = asn1_node_root(rapdu)
    while True:
        do = asn1_get_all(rapdu, i)
        if do.startswith(b"\x85"):
            encrypted_data = asn1_get_value(rapdu, i)
            do85 = do
        elif do.startswith(b"\x87"):
            encrypted_data = asn1_get_value(rapdu, i)
            do87 = do
        elif do.startswith(b"\x99"):
            do99 = do
        elif do.startswith(b"\x8E"):
            do8e = asn1_get_value(rapdu, i)
        if i[2] == len(rapdu) - 1:
            break
        i = asn1_node_next(rapdu, i)

    k = padding_method_2(
        sm_object.ssc + (do85 or b"") + (do87 or b"") + (do99 or b""), sm_object.pad_len
    )

    cc = compute_mac(sm_object.ks_mac, k, sm_object.mac_alg)

    if cc != do8e:
        raise ReplyAPDUError("[-] Reply APDU is not valid.")

    if encrypted_data:
        # If INS is even, remove the padding indicator (01)
        if do87 is not None:
            encrypted_data = encrypted_data[1:]
        # Decrypt
        if sm_object.enc_alg == "3DES":
            decrypted_data = DES3.new(sm_object.ks_enc, DES3.MODE_CBC, iv=bytes([0] * 8)).decrypt(
                encrypted_data
            )
        elif sm_object.enc_alg == "AES":
            ssc_enc = AES.new(sm_object.ks_enc, AES.MODE_ECB).encrypt(sm_object.ssc)
            decrypted_data = AES.new(sm_object.ks_enc, AES.MODE_CBC, iv=ssc_enc).decrypt(
                encrypted_data
            )

        # Remove padding
        decrypted_data = remove_padding(decrypted_data)

    return decrypted_data
