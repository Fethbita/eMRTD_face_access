#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module has functions for BAC and Secure Messaging (SM)"""

import hashlib
from os import urandom

from Crypto.Cipher import DES3
from Crypto.Util.strxor import strxor

from emrtd_face_access.apdu import APDU
from emrtd_face_access.card_comms import send
from emrtd_face_access.byte_operations import padding_method_2
from emrtd_face_access.secure_messaging import compute_key, compute_mac
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.byte_operations import nb


class SessionKeyEstablishmentError(Exception):
    """Exception to raise if an error occurs during establishment of BAC session keys."""


def establish_bac_session_keys(sm_object: SMObject, secret: bytes):
    """
    This function establishes session keys with the card
    Sets the necessary values of sm_object
    """
    # Calculate the SHA-1 hash of ‘MRZ_information’ and
    # take the most significant 16 bytes to form the basic access key seed
    ba_key_seed = hashlib.sha1(secret).digest()[:16]
    # Calculate the basic access keys (ba_key_enc and ba_key_mac)
    print("[+] Computing basic access keys...")
    ba_key_enc = compute_key(ba_key_seed, "enc", "3DES")
    ba_key_mac = compute_key(ba_key_seed, "mac", "3DES")

    ## AUTHENTICATION AND ESTABLISHMENT OF SESSION KEYS ##
    print("[+] Establishing session keys...")
    # exception caught in main program loop
    rnd_ic = send(sm_object, APDU(b"\x00", b"\x84", b"\x00", b"\x00", Le=b"\x08"))

    rnd_ifd = urandom(8)
    k_ifd = urandom(16)
    s = rnd_ifd + rnd_ic + k_ifd
    e_cipher = DES3.new(ba_key_enc, DES3.MODE_CBC, bytes([0] * 8))
    e_ifd = e_cipher.encrypt(s)
    m_ifd = compute_mac(ba_key_mac, padding_method_2(e_ifd, 8), "DES")
    # Construct command data for EXTERNAL AUTHENTICATE
    cmd_data = e_ifd + m_ifd

    # exception caught in main program loop
    resp_data_enc = send(
        sm_object,
        APDU(b"\x00", b"\x82", b"\x00", b"\x00", Lc=nb(len(cmd_data)), cdata=cmd_data, Le=b"\x28"),
    )
    m_ic = compute_mac(ba_key_mac, padding_method_2(resp_data_enc[:-8], 8), "DES")
    if m_ic != resp_data_enc[-8:]:
        raise SessionKeyEstablishmentError("[-] Encrypted message MAC is not correct!")

    d_cipher = DES3.new(ba_key_enc, DES3.MODE_CBC, bytes([0] * 8))
    resp_data = d_cipher.decrypt(resp_data_enc[:-8])
    if resp_data[:8] != rnd_ic:
        raise SessionKeyEstablishmentError(
            "[-] Received RND.IC DOES NOT match with the earlier RND.IC"
        )
    if resp_data[8:16] != rnd_ifd:
        raise SessionKeyEstablishmentError(
            "[-] Received RND.IFD DOES NOT match with the generated RND.IFD"
        )

    k_ic = resp_data[16:]

    # Calculate XOR of KIFD and KIC
    ses_key_seed = strxor(k_ifd, k_ic)
    # Calculate session keys (ks_enc and ks_mac)
    print("[+] Computing session keys...")
    ks_enc = compute_key(ses_key_seed, "enc", "3DES")
    ks_mac = compute_key(ses_key_seed, "mac", "3DES")

    # Calculate send sequence counter
    ssc = rnd_ic[-4:] + rnd_ifd[-4:]

    sm_object.enc_alg = "3DES"
    sm_object.mac_alg = "DES"
    sm_object.pad_len = 8
    sm_object.ks_enc = ks_enc
    sm_object.ks_mac = ks_mac
    sm_object.ssc = ssc
