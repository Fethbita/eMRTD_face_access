#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module does Password Authenticated Connection Establishment (PACE)
CURRENTLY IS NOT COMPLETELY IMPLEMENTED! NOT SUPPORTED YET!
"""

from typing import List, Tuple, Dict, Union
import hashlib

from Crypto.Cipher import DES3, AES
from M2Crypto import EC, BIO  # , EVP

# from cryptography.hazmat.primitives.asymmetric import ec

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_node_first_child,
    asn1_node_next,
    asn1_get_value,
    asn1_get_value_of_type,
)

# from emrtd_face_access.apdu import APDU
# from emrtd_face_access.card_comms import send
from emrtd_face_access.asn1 import encode_oid_string, asn1_len
from emrtd_face_access.secure_messaging import compute_key
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.extract_ldif import execute


class PACEError(Exception):
    """Exception to raise when a PACE Error occurs."""


def pace(security_infos_efca: List[bytes], sm_object: SMObject, secret: bytes, pub_key_ref: str):
    """
    List of Security Infos from EF.CardAccesss
    SMObject,
    Secret (MRZ info or CAN)
    pub_key_ref choices ("MRZ" or "CAN")
    """
    openssl_nid_to_name = {
        409: "prime192v1",
        923: "brainpoolP192r1",
        713: "secp224r1",
        925: "brainpoolP224r1",
        415: "prime256v1",
        927: "brainpoolP256r1",
        929: "brainpoolP320r1",
        715: "secp384r1",
        931: "brainpoolP384r1",
        933: "brainpoolP512r1",
        716: "secp521r1",
    }

    domain_parameters: Dict[int, Union[Tuple[str], Tuple[int, str]]] = {
        0: ("1024-bit MODP Group with 160-bit Prime Order Subgroup",),
        1: ("2048-bit MODP Group with 224-bit Prime Order Subgroup",),
        2: ("2048-bit MODP Group with 256-bit Prime Order Subgroup",),
        3: ("Reserved for Future Use",),
        4: ("Reserved for Future Use",),
        5: ("Reserved for Future Use",),
        6: ("Reserved for Future Use",),
        7: ("Reserved for Future Use",),
        8: (
            409,
            "NIST P-192 (secp192r1)",
        ),  #  https://stackoverflow.com/a/41953717/6077951
        9: (
            923,
            "BrainpoolP192r1",
        ),
        10: (
            713,
            "NIST P-224 (secp224r1) (can't be used with im)",
        ),
        11: (
            925,
            "BrainpoolP224r1",
        ),
        12: (
            415,
            "NIST P-256 (secp256r1)",
        ),  #  https://stackoverflow.com/a/41953717/6077951
        13: (
            927,
            "BrainpoolP256r1",
        ),
        14: (
            929,
            "BrainpoolP320r1",
        ),
        15: (
            715,
            "NIST P-384 (secp384r1)",
        ),
        16: (
            931,
            "BrainpoolP384r1",
        ),
        17: (
            933,
            "BrainpoolP512r1",
        ),
        18: (
            716,
            "NIST P-521 (secp521r1)",
        ),
        19: ("Reserved for Future Use",),
        20: ("Reserved for Future Use",),
        21: ("Reserved for Future Use",),
        22: ("Reserved for Future Use",),
        23: ("Reserved for Future Use",),
        24: ("Reserved for Future Use",),
        25: ("Reserved for Future Use",),
        26: ("Reserved for Future Use",),
        27: ("Reserved for Future Use",),
        28: ("Reserved for Future Use",),
        29: ("Reserved for Future Use",),
        30: ("Reserved for Future Use",),
        31: ("Reserved for Future Use",),
    }

    id_pace = "0.4.0.127.0.7.2.2.4"
    pace_protocol_dict = {
        encode_oid_string(id_pace + ".1.1"): "id-PACE-DH-GM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".1.2"): "id-PACE-DH-GM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".1.3"): "id-PACE-DH-GM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".1.4"): "id-PACE-DH-GM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".2.1"): "id-PACE-ECDH-GM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".2.2"): "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".2.3"): "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".2.4"): "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".3.1"): "id-PACE-DH-IM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".3.2"): "id-PACE-DH-IM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".3.3"): "id-PACE-DH-IM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".3.4"): "id-PACE-DH-IM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".4.1"): "id-PACE-ECDH-IM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".4.2"): "id-PACE-ECDH-IM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".4.3"): "id-PACE-ECDH-IM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".4.4"): "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".6.2"): "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".6.3"): "id-PACE-ECDH-CAM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".6.4"): "id-PACE-ECDH-CAM-AES-CBC-CMAC-256",
    }

    supported_pace: List[Tuple[bytes, int]] = find_paceinfos(security_infos_efca)

    if supported_pace == []:
        raise PACEError("[-] No supported PACEInfo found.")

    used_pace = supported_pace[0]
    used_pace_str = pace_protocol_dict[used_pace[0]].split("-")

    if pub_key_ref == "MRZ":
        key_seed = hashlib.sha1(secret).digest()
    if used_pace_str[4] == "3DES":
        k_dec = compute_key(key_seed, "pace", "3DES")
    else:  # AES
        k_dec = compute_key(key_seed, "pace", "AES-" + used_pace_str[7])

    payload = b"\x80" + used_pace[0][1:]
    if pub_key_ref == "MRZ":
        payload += b"\x83" + b"\x01" + b"\x01"
    elif pub_key_ref == "CAN":
        payload += b"\x83" + b"\x01" + b"\x02"
    else:
        raise PACEError("[-] Only MRZ and CAN are supported.")

    # if more than one set of DomainParameters is available:
    # payload = b"\x84" + reference of ...

    # MSE: AT
    ########data = send(sm_object, APDU(b"\x00", b"\x22", b"\xC1", b"\xA4", Lc=nb(len(payload)), cdata=payload))

    # Query encrypted nonce
    ########data = send(sm_object,APDU(b"\x10", b"\x86", b"\x00", b"\x00", Lc=b"\x02", cdata=b"\x7C\x00", Le=b"\x00"))
    data = bytes.fromhex("7C12801095A3A016522EE98D01E76CB6B98B42C3")
    # THE EXAMPLES ARE TAKEN FROM ICAO Doc 9303-11 App G-1

    i = asn1_node_root(data)  # Dynamic authentication data (0x7C)
    i = asn1_node_first_child(data, i)  # Encrypted Nonce (0x80)
    encrypted_nonce = asn1_get_value(data, i)

    if used_pace_str[4] == "3DES":
        decrypted_nonce = DES3.new(k_dec, DES3.MODE_CBC, iv=bytes([0] * 8)).decrypt(encrypted_nonce)
    else:
        decrypted_nonce = AES.new(k_dec, AES.MODE_CBC, iv=bytes([0] * 16)).decrypt(encrypted_nonce)

    assert decrypted_nonce == bytes.fromhex("3F00C4D39D153F2B2A214A078D899B22")

    if used_pace_str[3] == "GM":
        if used_pace_str[2] == "ECDH":
            used_domain_par = domain_parameters[used_pace[1]]
            if not isinstance(used_domain_par[0], int):
                raise PACEError("[-] These Domain parameters are not supported.")

            # ec_key_pair = EC.gen_params(used_domain_par[0])
            # ec_key_pair.gen_key()
            ec_key_pair = EC.load_key("tests/brainpoolP256r1.pem")
            ec_pub_key = ec_key_pair.pub().get_key()

            payload = b"\x81" + asn1_len(ec_pub_key) + ec_pub_key
            payload = b"\x7C" + asn1_len(payload) + payload

            # data = send(sm_object,APDU(b"\x10", b"\x86", b"\x00", b"\x00", Lc=nb(len(payload)), cdata=payload, Le=b"\x00"))
            data = bytes.fromhex(
                "7C43824104824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F5730D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54"
            )

            i = asn1_node_root(data)  # Dynamic Authentication Data (0x7C)
            i = asn1_node_first_child(data, i)  # Mapping Data (0x82)

            card_pace_pub_key = EC.pub_key_from_params(
                used_domain_par[0], asn1_get_value(data, i)
            )  # https://gitlab.com/m2crypto/m2crypto/-/blob/master/tests/test_ecdsa.py

            print((card_pace_pub_key.pub().get_key().hex()))
            # A different ecdsa library might be needed.
            shared_secret = ec_key_pair.compute_dh_key(card_pace_pub_key.pub())

            ec_pem_buf = BIO.MemoryBuffer()
            card_pace_pub_key.save_pub_key_bio(ec_pem_buf)
            ec_pem = ec_pem_buf.read()

            cmd = (
                "openssl ecparam -name "
                + openssl_nid_to_name[used_domain_par[0]]
                + " -param_enc explicit -text -noout"
            )
            ec_parameters, err = execute(cmd, ec_pem)

            generator = bytes.fromhex(
                ec_parameters.split(b"Generator (uncompressed):", 1)[1]
                .split(b"Order:", 1)[0]
                .replace(b"    ", b"")
                .replace(b":", b"")
                .replace(b"\n", b"")
                .decode("utf-8")
            )
            if generator[0] != 0x04:
                raise PACEError("[-] Problem in openssl.")

            generator = generator[1:]
            generator_x = generator[: len(generator) // 2]
            generator_y = generator[len(generator) // 2 :]


def find_paceinfos(security_infos: List[bytes]) -> List[Tuple[bytes, int]]:
    """
    From SecurityInfos find Chip Authentication Public Keys and return them as\n
    list(list(key_id, pub_key))\n
    If key id doesn't exist, it is an empty bytes b""
    """
    id_pace = "0.4.0.127.0.7.2.2.4"
    pace_protocol_dict = {
        encode_oid_string(id_pace + ".1.1"): "id-PACE-DH-GM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".1.2"): "id-PACE-DH-GM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".1.3"): "id-PACE-DH-GM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".1.4"): "id-PACE-DH-GM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".2.1"): "id-PACE-ECDH-GM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".2.2"): "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".2.3"): "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".2.4"): "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".3.1"): "id-PACE-DH-IM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".3.2"): "id-PACE-DH-IM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".3.3"): "id-PACE-DH-IM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".3.4"): "id-PACE-DH-IM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".4.1"): "id-PACE-ECDH-IM-3DES-CBC-CBC",
        encode_oid_string(id_pace + ".4.2"): "id-PACE-ECDH-IM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".4.3"): "id-PACE-ECDH-IM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".4.4"): "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
        encode_oid_string(id_pace + ".6.2"): "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
        encode_oid_string(id_pace + ".6.3"): "id-PACE-ECDH-CAM-AES-CBC-CMAC-192",
        encode_oid_string(id_pace + ".6.4"): "id-PACE-ECDH-CAM-AES-CBC-CMAC-256",
    }

    supported_pace: List[Tuple[bytes, int]] = []

    for sec_info in security_infos:
        i = asn1_node_root(sec_info)
        i = asn1_node_first_child(sec_info, i)  # get OID for this SecurityInfo
        si_oid = asn1_get_all(sec_info, i)
        if si_oid not in pace_protocol_dict:
            continue
        i = asn1_node_next(sec_info, i)  # get version for this PACEInfo
        si_ver = asn1_get_value_of_type(sec_info, i, "INTEGER")
        if si_ver != b"\x02":  # Other versions are not supported
            continue

        i = asn1_node_next(sec_info, i)  # get parameterID for this PACEInfo
        si_parameter_info = int.from_bytes(
            asn1_get_value_of_type(sec_info, i, "INTEGER"), byteorder="big"
        )
        supported_pace.append((si_oid, si_parameter_info))

    return supported_pace