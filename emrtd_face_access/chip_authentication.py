#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module does Chip Authentication (CA)"""

from typing import List, Dict

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
from emrtd_face_access.asn1 import encode_oid_string, asn1_len
from emrtd_face_access.secure_messaging import compute_key
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.byte_operations import nb


class ChipAuthenticationError(Exception):
    """Exception to raise when a Chip Authentication Error occurs."""


def chip_auth(security_infos: List[bytes], sm_object: SMObject):
    """Do Chip Authentication"""
    # Support of Chip Authentication is indicated
    # by the presence of corresponding SecurityInfos in DG14.
    # If available, the terminal MAY read and verify DG14 and perform Chip Authentication.
    id_ca = "0.4.0.127.0.7.2.2.3"
    ca_protocol_dict = {
        encode_oid_string(id_ca + ".1.1"): "id-CA-DH-3DES-CBC-CBC",
        encode_oid_string(id_ca + ".1.2"): "id-CA-DH-AES-CBC-CMAC-128",
        encode_oid_string(id_ca + ".1.3"): "id-CA-DH-AES-CBC-CMAC-192",
        encode_oid_string(id_ca + ".1.4"): "id-CA-DH-AES-CBC-CMAC-256",
        encode_oid_string(id_ca + ".2.1"): "id-CA-ECDH-3DES-CBC-CBC",
        encode_oid_string(id_ca + ".2.2"): "id-CA-ECDH-AES-CBC-CMAC-128",
        encode_oid_string(id_ca + ".2.3"): "id-CA-ECDH-AES-CBC-CMAC-192",
        encode_oid_string(id_ca + ".2.4"): "id-CA-ECDH-AES-CBC-CMAC-256",
    }

    try:
        supported_ca_algs: Dict[bytes, List[bytes]] = find_supported_ca_algs(security_infos)
    except ValueError as ex:
        raise ChipAuthenticationError("[-] find_supported_ca_algs failed") from ex

    ca_pub_keys: List[List[bytes]] = find_ca_pub_keys(security_infos)

    k = list(supported_ca_algs.keys())
    v = list(supported_ca_algs.values())
    max_alg_oid = max(k)
    max_alg = ca_protocol_dict[max_alg_oid].split("-")
    max_alg_key_ids = v[k.index(max_alg_oid)]
    ca_pub_key = b""
    if len(ca_pub_keys) == 1:
        ca_pub_key = ca_pub_keys[0][1]
    elif len(max_alg_key_ids) == 0:
        raise ChipAuthenticationError(
            "[-] The integer keyId MUST be used if the MRTD "
            "chip provides multiple public keys for Chip Authentication. "
        )
    else:
        for sublist in ca_pub_keys:
            if sublist[0] == max_alg_key_ids[0]:  # Always use the first key if multiple keys exist
                ca_pub_key = sublist[1]
                break
    if ca_pub_key == b"":
        raise ChipAuthenticationError(
            "[-] Proper Chip Authentication public key couldn't be found!"
        )

    if max_alg[2] == "DH":
        raise NotImplementedError(
            "[!] This type of Chip Authentication (CA) is not implemented yet!"
        )
        # if max_alg[3] == "3DES":
        #     pass
        # else:
        #     pass
    elif max_alg[2] == "ECDH":
        pk_ic = EC.pub_key_from_der(ca_pub_key)
        if pk_ic.check_key() != 1:
            raise ChipAuthenticationError(
                "[-] Chip Authentication (CA) failed! Problem in EC Public Key!"
            )

        dh_key_pair = EC.pub_key_from_der(ca_pub_key)
        # Might be unsupported soon. Don't call get_der() method before this line
        # M2Crypto caches the result of get_der method!!!
        dh_key_pair.gen_key()

        if max_alg[3] == "3DES":
            dh_eph_pub_key = dh_key_pair.get_key()
            payload = b"\x91" + asn1_len(dh_eph_pub_key) + dh_eph_pub_key
            if len(max_alg_key_ids) != 0:  # Have tested
                payload += b"\x84" + asn1_len(max_alg_key_ids[0]) + max_alg_key_ids[0]

            # exception caught in main program loop
            send(
                sm_object,
                APDU(b"\x00", b"\x22", b"\x41", b"\xA6", Lc=nb(len(payload)), cdata=payload),
            )

            shared_secret = dh_key_pair.compute_dh_key(pk_ic.pub())
            kenc = compute_key(shared_secret, "enc", "3DES")
            kmac = compute_key(shared_secret, "mac", "3DES")

            sm_object.enc_alg = "3DES"
            sm_object.mac_alg = "DES"
            sm_object.pad_len = 8
            sm_object.ks_enc = kenc
            sm_object.ks_mac = kmac
            sm_object.ssc = b"\x00\x00\x00\x00\x00\x00\x00\x00"
            print("[+] Chip Authentication (CA) completed successfully!")

        else:
            # crypto_mechanism = asn1_get_value_of_type(
            #    max_alg_oid, asn1_node_root(max_alg_oid), "OBJECT IDENTIFIER"
            # )
            payload = b"\x80" + max_alg_oid[1:]
            if len(max_alg_key_ids) != 0:  # Haven't tested
                payload += b"\x84" + asn1_len(max_alg_key_ids[0]) + max_alg_key_ids[0]

            # exception caught in main program loop
            send(
                sm_object,
                APDU(b"\x00", b"\x22", b"\x41", b"\xA4", Lc=nb(len(payload)), cdata=payload),
            )

            dh_eph_pub_key = dh_key_pair.get_key()
            payload = b"\x80" + asn1_len(dh_eph_pub_key) + dh_eph_pub_key
            payload = b"\x7C" + asn1_len(payload) + payload

            # exception caught in main program loop
            data = send(
                sm_object,
                APDU(b"\x00", b"\x86", b"\x00", b"\x00", Lc=nb(len(payload)), cdata=payload),
            )

            shared_secret = dh_key_pair.compute_dh_key(pk_ic.pub())
            kenc = compute_key(shared_secret, "enc", "AES-" + max_alg[6])
            kmac = compute_key(shared_secret, "mac", "AES-" + max_alg[6])

            sm_object.enc_alg = "AES"
            sm_object.mac_alg = "AES-CMAC"
            sm_object.pad_len = 16
            sm_object.ks_enc = kenc
            sm_object.ks_mac = kmac
            sm_object.ssc = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            print("[+] Chip Authentication (CA) completed successfully!")


def find_supported_ca_algs(security_infos: List[bytes]) -> Dict[bytes, List[bytes]]:
    """
    From SecurityInfos find supported Chip Authentication algorithms and return them as\n
    Dict[bytes, List[bytes]]
    If key id doesn't exist, list of bytes is an empty list []""
    """
    id_ca = "0.4.0.127.0.7.2.2.3"
    ca_protocols = [
        encode_oid_string(id_ca + ".1.1"),
        encode_oid_string(id_ca + ".1.2"),
        encode_oid_string(id_ca + ".1.3"),
        encode_oid_string(id_ca + ".1.4"),
        encode_oid_string(id_ca + ".2.1"),
        encode_oid_string(id_ca + ".2.2"),
        encode_oid_string(id_ca + ".2.3"),
        encode_oid_string(id_ca + ".2.4"),
    ]
    supported_ca_algs: Dict[bytes, List[bytes]] = {}

    for sec_info in security_infos:
        i = asn1_node_root(sec_info)
        last_byte = i[2]
        i = asn1_node_first_child(sec_info, i)  # get OID for this SecurityInfo
        si_oid = asn1_get_all(sec_info, i)

        if si_oid not in ca_protocols:
            continue

        i = asn1_node_next(sec_info, i)
        if asn1_get_value_of_type(sec_info, i, "INTEGER") != b"\x01":
            continue

        if i[2] == last_byte:
            supported_ca_algs[si_oid] = supported_ca_algs.get(si_oid, [])
            continue

        i = asn1_node_next(sec_info, i)
        key_id = asn1_get_value_of_type(sec_info, i, "INTEGER")
        supported_ca_algs[si_oid] = supported_ca_algs.get(si_oid, []) + [key_id]

    return supported_ca_algs


def find_ca_pub_keys(security_infos: List[bytes]) -> List[List[bytes]]:
    """
    From SecurityInfos find Chip Authentication Public Keys and return them as\n
    list(list(key_id, pub_key))\n
    If key id doesn't exist, it is an empty bytes b""
    """
    ca_pub_keys: List[List[bytes]] = []
    for sec_info in security_infos:
        i = asn1_node_root(sec_info)
        last_byte = i[2]
        i = asn1_node_first_child(sec_info, i)  # get OID for this SecurityInfo
        si_oid = asn1_get_all(sec_info, i)

        if si_oid not in [
            encode_oid_string("0.4.0.127.0.7.2.2.1.1"),  # id-PK-DH
            encode_oid_string("0.4.0.127.0.7.2.2.1.2"),  # id-PK-ECDH
        ]:
            continue
        i = asn1_node_next(sec_info, i)
        ca_pub_key = asn1_get_all(sec_info, i)
        if i[2] == last_byte:
            ca_pub_keys.append([b"", ca_pub_key])
            continue
        i = asn1_node_next(sec_info, i)
        key_id = asn1_get_value_of_type(sec_info, i, "INTEGER")
        ca_pub_keys.append([key_id, ca_pub_key])
    return ca_pub_keys
