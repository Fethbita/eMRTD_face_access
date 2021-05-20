#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module has functions related to Data Groups (DG) in MRTD"""

from typing import Dict, Tuple, List
import hashlib
import hmac

import PySimpleGUI as sg

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_get_value,
    asn1_get_value_of_type,
    asn1_node_next,
    asn1_node_first_child,
)

from emrtd_face_access.apdu import APDU
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.card_comms import send
from emrtd_face_access.asn1 import len2int
from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print


class EFReadError(Exception):
    """Raised if an error occurs during data read from a file."""


def read_data_from_ef(window: sg.Window, sm_object: SMObject, fid: bytes, fname: str) -> bytes:
    """
    Read the data from file id fid and return

    sm_object -- Necessary secure messaging object (Encryption session key etc.)
    fid -- File id
    fname -- Printed file name
    :returns: data from the file
    """
    # Select File
    print("[+] Selecting file: " + fname)

    # exception caught in main program loop
    send(sm_object, APDU(b"\x00", b"\xA4", b"\x02", b"\x0C", Lc=b"\x02", cdata=fid))

    # Read Binary of first four bytes
    print("[+] Read first 4 bytes of selected file...")

    # exception caught in main program loop
    data = send(sm_object, APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x04"))

    if data == b"":
        raise EFReadError("[-] No reply from card")
    elif len(data) != 4:
        raise EFReadError("[-] Broken reply from card")

    data_len = len2int(data)

    offset = 4

    # Read the rest of the bytes
    print("[+] Read the rest of the bytes of selected file...")
    # IAS_ECC_v1 page 121 "Particular issue for the READ BINARY command"
    while offset < data_len:
        if (
            data_len - offset < 0xFA
        ):  # 0xFA because all the cards I have access to only send 250 bytes in BAC SM 242 in AES SM
            le = bytes([data_len - offset])
        else:
            le = b"\x00"
        window.write_event_value(
            "-PROGRESS BAR-",
            [offset, data_len],
        )

        # exception caught in main program loop
        decrypted_data = send(
            sm_object,
            APDU(b"\x00", b"\xB0", bytes([offset >> 8]), bytes([offset & 0xFF]), Le=le),
        )

        if decrypted_data == b"":
            raise EFReadError("[-] No reply from card")

        data += decrypted_data
        offset += len(decrypted_data)

    window.write_event_value(
        "-PROGRESS BAR-",
        [offset, data_len],
    )

    if offset != data_len:
        raise EFReadError("[-] Error while processing a file.")
    window.write_event_value(
        "-PROGRESS BAR-",
        [0, 100],
    )

    return data


def parse_efcom(efcom: bytes) -> Dict[bytes, str]:
    """
    Parse EF.COM file and return the files mentioned as a dict
    """
    i = asn1_node_root(efcom)
    lst = list(i)
    # LDS Version length is 4
    lst[0] = lst[1]
    lst[1] = lst[0] + 3
    lst[2] = lst[1] + 3
    i = (lst[0], lst[1], lst[2])
    lds_ver = asn1_get_value(efcom, i)
    print(
        "[+] LDS version: {}.{}".format(
            *[int(lds_ver[i : i + 2].decode("utf-8")) for i in range(0, 4, 2)]
        )
    )

    # Unicode Version number length is 6
    lst[0] = lst[2] + 1
    lst[1] = lst[0] + 3
    lst[2] = lst[1] + 5
    i = (lst[0], lst[1], lst[2])
    unicode_ver = asn1_get_value(efcom, i)
    print(
        "[+] Unicode version: {}.{}.{}".format(
            *[int(unicode_ver[i : i + 2].decode("utf-8")) for i in range(0, 6, 2)]
        )
    )

    i = asn1_node_next(efcom, i)
    rest = asn1_get_value(efcom, i)

    tag2dg: Dict[int, Tuple[bytes, str]] = {
        0x60: (b"\x1E", "EF.COM"),
        0x61: (b"\x01", "EF.DG1"),
        0x75: (b"\x02", "EF.DG2"),
        0x63: (b"\x03", "EF.DG3"),
        0x76: (b"\x04", "EF.DG4"),
        0x65: (b"\x05", "EF.DG5"),
        0x66: (b"\x06", "EF.DG6"),
        0x67: (b"\x07", "EF.DG7"),
        0x68: (b"\x08", "EF.DG8"),
        0x69: (b"\x09", "EF.DG9"),
        0x6A: (b"\x0A", "EF.DG10"),
        0x6B: (b"\x0B", "EF.DG11"),
        0x6C: (b"\x0C", "EF.DG12"),
        0x6D: (b"\x0D", "EF.DG13"),
        0x6E: (b"\x0E", "EF.DG14"),
        0x6F: (b"\x0F", "EF.DG15"),
        0x70: (b"\x10", "EF.DG16"),
        0x77: (b"\x1D", "EF.SOD"),
    }

    dg_list = {tag2dg[byte][0]: tag2dg[byte][1] for byte in rest}

    return dg_list


def get_dg_numbers(data_group_hash_values: bytes) -> Dict[bytes, str]:
    """
    Get DG numbers from EF.SOD data group hash values.
    """
    dg_list = []

    i = asn1_node_root(data_group_hash_values)
    last = i[2]
    i = asn1_node_first_child(data_group_hash_values, i)

    j = asn1_node_first_child(data_group_hash_values, i)
    dg_list.append(asn1_get_value_of_type(data_group_hash_values, j, "INTEGER"))
    while i[2] != last:
        i = asn1_node_next(data_group_hash_values, i)
        j = asn1_node_first_child(data_group_hash_values, i)
        dg_list.append(asn1_get_value_of_type(data_group_hash_values, j, "INTEGER"))

    tag2dg: Dict[bytes, str] = {
        b"\x1E": "EF.COM",
        b"\x01": "EF.DG1",
        b"\x02": "EF.DG2",
        b"\x03": "EF.DG3",
        b"\x04": "EF.DG4",
        b"\x05": "EF.DG5",
        b"\x06": "EF.DG6",
        b"\x07": "EF.DG7",
        b"\x08": "EF.DG8",
        b"\x09": "EF.DG9",
        b"\x0A": "EF.DG10",
        b"\x0B": "EF.DG11",
        b"\x0C": "EF.DG12",
        b"\x0D": "EF.DG13",
        b"\x0E": "EF.DG14",
        b"\x0F": "EF.DG15",
        b"\x10": "EF.DG16",
        b"\x1D": "EF.SOD",
    }

    return {byte: tag2dg[byte] for byte in dg_list}


def assert_dg_hash(
    dg_file: bytes, data_group_hash_values: bytes, hash_alg: str, dg_number_bytes: bytes
) -> bool:
    """
    Calculate the hash over the DG file and compare that in the EF.SOD.
    """
    dg_number = int.from_bytes(dg_number_bytes, byteorder="big")
    # Only hashes for DG1-DG16 exist
    if dg_number < 1 and dg_number > 16:
        raise ValueError("[-] Only hashes for DG1-DG16 exist!")

    hash_object = hashlib.new(hash_alg)

    hash_object.update(dg_file)
    file_hash = hash_object.digest()

    current = 0
    i = asn1_node_root(data_group_hash_values)
    i = asn1_node_first_child(data_group_hash_values, i)
    while True:
        j = asn1_node_first_child(data_group_hash_values, i)
        current = int.from_bytes(
            asn1_get_value_of_type(data_group_hash_values, j, "INTEGER"),
            byteorder="big",
        )
        if current == dg_number:
            break
        i = asn1_node_next(data_group_hash_values, i)

    j = asn1_node_next(data_group_hash_values, j)
    hash_in_dg = asn1_get_value(data_group_hash_values, j)

    if not hmac.compare_digest(file_hash, hash_in_dg):
        print("[-] Potentially cloned document, hashes do not match!")
        return False
    print(f"[+] DG {dg_number} hash matches that on the EF.SOD.")
    return True


def get_dg1_content(dg1: bytes) -> bytes:
    """
    Read the MRZ from DG1 and return the MRZ
    """
    i = asn1_node_root(dg1)
    lst = list(i)
    lst[0] = lst[1]
    lst[1] = lst[0] + 3
    i = (lst[0], lst[1], lst[2])
    mrz = asn1_get_value(dg1, i)
    return mrz


def parse_security_infos(dg14: bytes) -> List[bytes]:
    """
    Return a list of SecurityInfo from SecurityInfos
    """
    i = asn1_node_root(dg14)

    if dg14[0] == 0x6E:  # strip DG14 tag (6E)
        i = asn1_node_first_child(dg14, i)

    last_byte = i[2]

    security_infos = []

    i = asn1_node_first_child(dg14, i)
    security_infos.append(asn1_get_all(dg14, i))
    if i[2] != last_byte:
        while True:
            i = asn1_node_next(dg14, i)
            security_infos.append(asn1_get_all(dg14, i))

            if i[2] == last_byte:
                break

    return security_infos
