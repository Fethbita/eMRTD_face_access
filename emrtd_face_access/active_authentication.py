#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module does Active Authentication (AA)"""

import hashlib
import hmac
from os import urandom
from typing import List

from M2Crypto import EC

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_node_first_child,
    asn1_node_next,
    asn1_get_value_of_type,
)
from emrtd_face_access.apdu import APDU
from emrtd_face_access.card_comms import send
from emrtd_face_access.asn1 import encode_oid_string, asn1_integer, asn1_sequence
from emrtd_face_access.secure_messaging_object import SMObject


class ActiveAuthenticationError(Exception):
    """Exception to raise when an Active Authentication Error occurs."""


def active_auth(dg15: bytes, sm_object: SMObject, security_infos: List[bytes]):
    """
    Do active authentication with DG15
    """
    # Generate 8 random bytes
    rnd_ifd = urandom(8)

    # exception caught in main program loop
    data = send(
        sm_object, APDU(b"\x00", b"\x88", b"\x00", b"\x00", Lc=b"\x08", cdata=rnd_ifd, Le=b"\x00")
    )

    if data == b"":
        raise ActiveAuthenticationError("[-] No reply from card.")

    i = asn1_node_root(dg15)
    i = asn1_node_first_child(dg15, i)
    pub_key = asn1_get_all(dg15, i)

    i = asn1_node_first_child(dg15, i)
    i = asn1_node_first_child(dg15, i)

    if asn1_get_all(dg15, i) == encode_oid_string("1.2.840.10045.2.1"):  # ECC
        r = data[: len(data) // 2]
        s = data[len(data) // 2 :]
        signature = asn1_sequence(asn1_integer(r) + asn1_integer(s))
        ec_pub = EC.pub_key_from_der(pub_key)
        if ec_pub.check_key() != 1:
            raise ActiveAuthenticationError(
                "[-] Active Authentication (AA) failed! Problem in EC Public Key!"
            )

        try:
            hash_type = find_hash_name(security_infos)
        except ValueError as ex:
            raise ActiveAuthenticationError(
                "[-] Active Authentication (AA) failed! Problem in Security Infos hash type!"
            ) from ex
        # for hash_type in ["sha224", "sha256", "sha384", "sha512"]:
        try:
            result = ec_pub.verify_dsa_asn1(hashlib.new(hash_type, rnd_ifd).digest(), signature)
        except EC.ECError as ex:
            print("[-] Error in EC function " + ex)
            raise ActiveAuthenticationError("[-] Error in verify_dsa_asn1 of M2Crypto.EC") from ex
        if result == 1:
            print("[+] Active Authentication (AA) completed successfully!")
        else:
            raise ActiveAuthenticationError("[-] Active Authentication (AA) failed!")

    elif asn1_get_all(dg15, i) == encode_oid_string("1.2.840.113549.1.1.1"):  # RSA
        j = asn1_node_root(pub_key)
        j = asn1_node_first_child(pub_key, j)
        j = asn1_node_next(pub_key, j)

        rsa_pub_key = asn1_get_value_of_type(pub_key, j, "BIT STRING")
        if rsa_pub_key[0] != 0x00:
            raise ActiveAuthenticationError(
                "[-] An issue with the RSA key! Padding 0x00 is expected"
            )

        rsa_pub_key = rsa_pub_key[1:]
        j = asn1_node_root(rsa_pub_key)
        j = asn1_node_first_child(rsa_pub_key, j)
        n_der = asn1_get_value_of_type(rsa_pub_key, j, "INTEGER")
        j = asn1_node_next(rsa_pub_key, j)
        e_der = asn1_get_value_of_type(rsa_pub_key, j, "INTEGER")
        n = int.from_bytes(n_der, byteorder="big")
        e = int.from_bytes(e_der, byteorder="big")

        # rsa_key = RSA.import_key(pub_key)
        # https://stackoverflow.com/a/60132608/6077951

        msg = int.from_bytes(data, byteorder="big")
        dec = pow(msg, e, n).to_bytes(len(data), byteorder="big")

        if dec[-1] == 0xCC:
            if dec[-2] == 0x38:
                hash_alg = "sha224"
            elif dec[-2] == 0x34:
                hash_alg = "sha256"
            elif dec[-2] == 0x36:
                hash_alg = "sha384"
            elif dec[-2] == 0x35:
                hash_alg = "sha512"
            t = 2
        elif dec[-1] == 0xBC:
            hash_alg = "sha1"
            t = 1
        else:
            raise ActiveAuthenticationError("[-] Error while Active Authentication!")

        def compare_aa(hash_object):
            # k = rsa_key.size_in_bits()
            # Lh = hash_object.digest_size * 8
            # Lm1 = (k - Lh - (8 * t) - 4 - 4) // 8
            D = dec[-hash_object.digest_size - t : -t]
            M1 = dec[1 : -hash_object.digest_size - t]
            Mstar = M1 + rnd_ifd
            hash_object.update(Mstar)
            Dstar = hash_object.digest()
            return hmac.compare_digest(D, Dstar)

        hash_object = hashlib.new(hash_alg)
        if compare_aa(hash_object):
            print("[+] Active Authentication (AA) completed successfully!")
        else:
            raise ActiveAuthenticationError("[-] Active Authentication (AA) failed!")


def find_hash_name(security_infos: List[bytes]) -> str:
    """
    Return the hashing algorithm for ECC AA from SecurityInfos (DG14)
    """
    for sec_info in security_infos:
        i = asn1_node_root(sec_info)
        i = asn1_node_first_child(sec_info, i)  # get OID for this SecurityInfo
        si_oid = asn1_get_all(sec_info, i)
        if si_oid != encode_oid_string("2.23.136.1.1.5"):  # id-icao-mrtd-security-aaProtocolObject
            continue
        i = asn1_node_next(sec_info, i)
        if asn1_get_value_of_type(sec_info, i, "INTEGER") != b"\x01":
            raise ValueError("[-] Version mismatch in DG14 AA SecurityInfo!")
        i = asn1_node_next(sec_info, i)
        signature_algorithm = asn1_get_all(sec_info, i)
        if signature_algorithm == encode_oid_string("0.4.0.127.0.7.1.1.4.1.2"):
            return "sha224"
        if signature_algorithm == encode_oid_string("0.4.0.127.0.7.1.1.4.1.3"):
            return "sha256"
        if signature_algorithm == encode_oid_string("0.4.0.127.0.7.1.1.4.1.4"):
            return "sha384"
        if signature_algorithm == encode_oid_string("0.4.0.127.0.7.1.1.4.1.5"):
            return "sha512"

    raise ValueError("[-] Unsupported signature algorithm in AA SecurityInfo!")
