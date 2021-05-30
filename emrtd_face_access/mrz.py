#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Module for MRZ related calculations and functions"""

from typing import Tuple
from datetime import datetime

from emrtd_face_access.apdu import APDU
from emrtd_face_access.card_comms import send
from emrtd_face_access.byte_operations import nb
from emrtd_face_access.secure_messaging_object import SMObject


def calculate_check_digit(data: str) -> str:
    """Calculate MRZ check digits for data.

    :data data: Data to calculate the check digit of
    :returns: check digit
    """

    # fmt: off
    values = {
        "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6,
        "7": 7, "8": 8, "9": 9, "<": 0, "A": 10, "B": 11,
        "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17,
        "I": 18, "J": 19, "K": 20, "L": 21, "M": 22, "N": 23,
        "O": 24, "P": 25, "Q": 26, "R": 27, "S": 28, "T": 29,
        "U": 30, "V": 31, "W": 32, "X": 33, "Y": 34, "Z": 35,
    }
    # fmt: on
    weights = [7, 3, 1]
    total = 0

    for counter, value in enumerate(data):
        total += weights[counter % 3] * values[value]
    return str(total % 10)


def estonia_read_mrz(sm_object: SMObject) -> Tuple[str, str, str, str, str]:
    """Read Estonian ID card information from personal data"""
    # reading personal data file (EstEID spec page 30)
    print("[+] Selecting IAS ECC applet AID: A000000077010800070000FE00000100...")
    ias_ecc_aid = bytes.fromhex("A000000077010800070000FE00000100")

    # exception caught in main program loop
    send(
        sm_object,
        APDU(b"\x00", b"\xA4", b"\x04", b"\x00", Lc=nb(len(ias_ecc_aid)), cdata=ias_ecc_aid),
    )
    print("[+] Selecting DF ID: 5000...")
    send(sm_object, APDU(b"\x00", b"\xA4", b"\x01", b"\x0C", Lc=b"\x02", cdata=b"\x50\x00"))
    send(sm_object, APDU(b"\x00", b"\xA4", b"\x01", b"\x0C", Lc=b"\x02", cdata=b"\x50\x07"))
    print("[+] Reading personal data files...")
    document_number = send(sm_object, APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x00")).decode(
        "utf8"
    )

    send(sm_object, APDU(b"\x00", b"\xA4", b"\x01", b"\x0C", Lc=b"\x02", cdata=b"\x50\x05"))
    date_of_birth = send(sm_object, APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x00"))[
        :10
    ].decode("utf8")
    date_of_birth = date_of_birth[-2:] + date_of_birth[3:5] + date_of_birth[:2]
    send(sm_object, APDU(b"\x00", b"\xA4", b"\x01", b"\x0C", Lc=b"\x02", cdata=b"\x50\x08"))
    date_of_expiry = send(sm_object, APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x00")).decode(
        "utf8"
    )
    date_of_expiry = date_of_expiry[-2:] + date_of_expiry[3:5] + date_of_expiry[:2]
    # Construct the 'MRZ information'
    print("[+] Constructing the MRZ information...")
    mrz_information = (
        document_number
        + calculate_check_digit(document_number)
        + date_of_birth
        + calculate_check_digit(date_of_birth)
        + date_of_expiry
        + calculate_check_digit(date_of_expiry)
    )

    send(sm_object, APDU(b"\x00", b"\xA4", b"\x01", b"\x0C", Lc=b"\x02", cdata=b"\x50\x01"))
    surname = send(sm_object, APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x00")).decode("utf8")
    send(sm_object, APDU(b"\x00", b"\xA4", b"\x01", b"\x0C", Lc=b"\x02", cdata=b"\x50\x02"))
    name = send(sm_object, APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x00")).decode("utf8")
    send(sm_object, APDU(b"\x00", b"\xA4", b"\x01", b"\x0C", Lc=b"\x02", cdata=b"\x50\x06"))
    personal_id_code = send(sm_object, APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x00")).decode(
        "utf8"
    )

    # Select LDS applet
    # A00000024710FF is applet id
    print("[+] Selecting LDS AID: A00000024710FF...")
    aid = bytes.fromhex("A00000024710FF")
    send(sm_object, APDU(b"\x00", b"\xA4", b"\x04", b"\x00", Lc=nb(len(aid)), cdata=aid))

    return mrz_information, document_number, personal_id_code, name, surname


def check_expiration(expiry_date: bytes) -> bool:
    """Check if the MRZ expiry date is older than today's date."""
    date = expiry_date.decode("utf-8")
    date_obj = datetime.strptime(date, "%y%m%d")
    if date_obj.date() < datetime.now().date():
        return False
    return True
