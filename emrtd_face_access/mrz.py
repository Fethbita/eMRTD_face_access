#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Module for MRZ related calculations and functions"""

from collections import Counter
from typing import Tuple, Union, List
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


def other_mrz(doc_no: str, birthdate: str, expirydate: str) -> str:
    """Create MRZ information"""
    return (
        doc_no.ljust(9, "<")
        + calculate_check_digit(doc_no)
        + birthdate
        + calculate_check_digit(birthdate)
        + expirydate
        + calculate_check_digit(expirydate)
    )


def verify_td1(mrz: List[str]) -> bool:
    """Verify TD1 MRZ"""
    if mrz[0][0] not in (
        "A",
        "C",
        "I",
        "R",
    ):  # Exception for Estonian residence permit cards "R"
        return False
    if mrz[0][1] in ("V"):
        return False
    # if mrz[0][2:5]: # ISSUING STATE OR ORGANIZATION
    if calculate_check_digit(mrz[0][5:14]) != mrz[0][14]:  # Document number
        return False
    # if mrz[0][15:30]: # OPTIONAL DATA ELEMENTS
    if calculate_check_digit(mrz[1][0:6]) != mrz[1][6]:  # Date of birth
        return False
    # if mrz[1][7]: # SEX
    if calculate_check_digit(mrz[1][8:14]) != mrz[1][14]:  # Date of expiry
        return False
    # if mrz[1][15:18]: # NATIONALITY
    # if mrz[1][18:29]: # OPTIONAL DATA ELEMENTS
    composite_check_line = mrz[0][5:30] + mrz[1][0:7] + mrz[1][8:15] + mrz[1][18:29]
    if calculate_check_digit(composite_check_line) != mrz[1][29]:
        return False
    # if mrz[2][0:30]: # NAME
    return True


def verify_td2(mrz: List[str]) -> bool:
    """Verify TD2 MRZ"""
    if mrz[0][0] not in ("A", "C", "I"):
        return False
    if mrz[0][1] in ("V"):
        return False
    # if mrz[0][2:5]: # ISSUING STATE OR ORGANIZATION
    # if mrz[0][5:36]: # NAME
    if calculate_check_digit(mrz[1][0:9]) != mrz[1][9]:  # Document number
        return False
    # if mrz[1][10:13]: # NATIONALITY
    if calculate_check_digit(mrz[1][13:19]) != mrz[1][19]:  # Date of birth
        return False
    # if mrz[1][20]: # SEX
    if calculate_check_digit(mrz[1][21:27]) != mrz[1][27]:  # Date of expiry
        return False
    # if mrz[1][28:35]: # Optional data elements
    composite_check_line = mrz[1][0:10] + mrz[1][13:20] + mrz[1][21:35]
    if calculate_check_digit(composite_check_line) != mrz[1][35]:
        return False
    return True


def verify_visa_mrvb(mrz: List[str]) -> bool:
    """Verify VISA MRVB"""
    if mrz[0][0] != "V":
        return False
    # if mrz[0][2:5]: # ISSUING STATE
    # if mrz[0][5:36]: # NAME
    if calculate_check_digit(mrz[1][0:9]) != mrz[1][9]:  # Document number
        return False
    # if mrz[1][10:13]: # NATIONALITY
    if calculate_check_digit(mrz[1][13:19]) != mrz[1][19]:  # Date of birth
        return False
    # if mrz[1][20]: # SEX
    if calculate_check_digit(mrz[1][21:27]) != mrz[1][27]:  # Valid until (date)
        return False
    # if mrz[1][28:36]: # Optional data elements
    return True


def verify_td3(mrz: List[str]) -> bool:
    """Verify TD3 MRZ"""
    if mrz[0][0] != "P":
        return False
    # if mrz[0][1]: # At the discretion of the issuing State or organization or "<"
    # if mrz[0][2:5]: # ISSUING STATE OR ORGANIZATION
    # if mrz[0][5:44]: # NAME
    if calculate_check_digit(mrz[1][0:9]) != mrz[1][9]:  # Passport number
        return False
    # if mrz[1][10:13]: # NATIONALITY
    if calculate_check_digit(mrz[1][13:19]) != mrz[1][19]:  # Date of birth
        return False
    # if mrz[1][20]: # SEX
    if calculate_check_digit(mrz[1][21:27]) != mrz[1][27]:  # Date of expiry
        return False
    if (mrz[1][28:42] == "<" * 14 and (mrz[1][42] != "<" or mrz[1][42] != "0")) or (
        calculate_check_digit(mrz[1][28:42]) != mrz[1][42]
    ):  # Personal number or other optional data elements
        return False
    composite_check_line = mrz[1][0:10] + mrz[1][13:20] + mrz[1][21:43]
    if calculate_check_digit(composite_check_line) != mrz[1][43]:
        return False
    return True


def verify_visa_mrva(mrz: List[str]) -> bool:
    """Verify VISA MRVA"""
    if mrz[0][0] != "V":
        return False
    # if mrz[0][1]: # At the discretion of the issuing State or organization or "<"
    # if mrz[0][2:5]: # ISSUING STATE
    # if mrz[0][5:44]: # NAME
    if calculate_check_digit(mrz[1][0:9]) != mrz[1][9]:  # Passport or document number
        return False
    # if mrz[1][10:13]: # NATIONALITY
    if calculate_check_digit(mrz[1][13:19]) != mrz[1][19]:  # Date of birth
        return False
    # if mrz[1][20]: # SEX
    if calculate_check_digit(mrz[1][21:27]) != mrz[1][27]:  # Valid until (date)
        return False
    # if mrz[1][28:44]: # Optional data elements

    return True


def parse_mrz_ocr(text: str) -> Union[List[str], None]:
    """Parse OCR result and check if MRZ is valid"""
    lines = text.split()
    lens = Counter([len(i) for i in lines])

    if lens[30] == 3:  # TD1
        lines = [i for i in lines if len(i) == 30]
        if verify_td1(lines):
            return lines
    elif lens[36] == 2:  # TD2 | MRV-B VISA
        lines = [i for i in lines if len(i) == 36]
        if verify_td2(lines):  # or verify_visa_mrvb(lines):
            return lines
    elif lens[44] == 2:  # TD3 | MRV-A VISA
        lines = [i for i in lines if len(i) == 44]
        if verify_td3(lines):  # or verify_visa_mrva(lines):
            return lines

    return None


def parse_name_surname(name_surname: str) -> Tuple[str, str]:
    """Parse and return name surname from the MRZ"""
    name_surname = name_surname.replace("<", " ")
    fields = name_surname.split("  ")
    fields = [x for x in fields if x.strip()]
    if len(fields) == 2:
        return fields[0], fields[1]
    if len(fields) == 1:
        return fields[0], ""

    return "", ""


def parse_mrz_text(text: List[str]) -> Tuple[str, str, str, str, str, str]:
    """Get necessary information from MRZ"""
    if len(text) == 3:  # TD1
        doc_no = text[0][5:14]  # + text[0][14]
        birthdate = text[1][0:6]  # + text[1][6]
        expiry_date = text[1][8:14]  # + text[1][14]
        name = text[2][0:30]
    elif len(text) == 2 and len(text[0]) == 36 and len(text[1]) == 36:  # TD2 | MRV-B VISA
        doc_no = text[1][0:9]  # + text[1][9]
        birthdate = text[1][13:19]  # + text[1][19]
        expiry_date = text[1][21:27]  # + text[1][27]
        name = text[0][5:36]
    elif len(text) == 2 and len(text[0]) == 44 and len(text[1]) == 44:  # TD3 | MRV-A VISA
        doc_no = text[1][0:9]  # + text[1][9]
        birthdate = text[1][13:19]  # + text[1][19]
        expiry_date = text[1][21:27]  # + text[1][27]
        name = text[0][5:44]
    country = text[0][2:5]
    name, surname = parse_name_surname(name)

    return doc_no, birthdate, expiry_date, country, name, surname


def check_expiration(expiry_date: bytes) -> bool:
    """Check if the MRZ expiry date is older than today's date."""
    date = expiry_date.decode("utf-8")
    date_obj = datetime.strptime(date, "%y%m%d")
    if date_obj.date() < datetime.now().date():
        return False
    return True
