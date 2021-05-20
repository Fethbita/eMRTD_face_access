#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""The main program loop emrtd_face_access"""

import os

# import sys
# import termios
import threading
import argparse
from typing import Union, TextIO, BinaryIO
from pathlib import Path
from queue import Queue

import PySimpleGUI as sg
from smartcard.util import toHexString
from smartcard.Exceptions import CardConnectionException
from tinydb import TinyDB, Query

from emrtd_face_access.apdu import APDU
from emrtd_face_access.card_comms import send, wait_for_card, CardCommunicationError
from emrtd_face_access.mrz import estonia_read_mrz, other_mrz, parse_mrz_text, check_expiration
from emrtd_face_access.bac import establish_bac_session_keys, SessionKeyEstablishmentError
from emrtd_face_access.file_operations import (
    EFReadError,
    read_data_from_ef,
    parse_efcom,
    get_dg_numbers,
    assert_dg_hash,
    get_dg1_content,
    parse_security_infos,
)
from emrtd_face_access.passive_authentication import (
    passive_auth,
    PassiveAuthenticationCriticalError,
)
from emrtd_face_access.chip_authentication import chip_auth, ChipAuthenticationError
from emrtd_face_access.active_authentication import active_auth, ActiveAuthenticationError
from emrtd_face_access.image_operations import get_jpeg_im
from emrtd_face_access.face_compare import jpeg_to_png
from emrtd_face_access.ee_valid import check_validity, download_certs
from emrtd_face_access.ocr import capture_mrz
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.log_operations import create_output_folder
from emrtd_face_access.icao_pkd_load import build_store
from emrtd_face_access.byte_operations import nb
from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print

# fmt: off
atr_exceptions = [
    # Estonian Identity Card (EstEID 3.0 contactless)
    [0x3B, 0x89, 0x80, 0x01, 0x4D, 0x54, 0x43, 0x4F, 0x53, 0x70, 0x02, 0x01, 0x05, 0x38],
    # Estonian Identity Card (EstEID 3.0 "JavaCard" cold)
    [0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0xA8],
    # iEstonian Identity Card (EstEID 3.0 (18.01.2011) warm)
    [0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF],
]
# fmt: on


def main(
    window: sg.Window,
    args: argparse.Namespace,
    db: TinyDB,
    q: Queue,
    q2: Queue,
    lock: threading.Lock,
    lock2: threading.Lock,
    first_run: bool,
) -> None:
    """main function"""

    # Get dir arguments else fallback to EE certs
    CSCA_certs_dir = args.certs or Path("certs/csca_certs")
    crls_dir = args.certs or Path("certs/crls")
    output_dir = args.output
    output_files = not args.output is None
    camera_id = -1
    outfile: Union[TextIO, BinaryIO]

    if (args.online and first_run) or (
        not os.path.isdir(CSCA_certs_dir) or not os.path.isdir(crls_dir)
    ):
        window.write_event_value(
            "-DOWNLOAD CSCA CERT AND CRL-",
            [True, "text_download_csca_crl", "Downloading CSCA certificates and CRLs...", "white"],
        )
        download_certs(CSCA_certs_dir, crls_dir)
        window.write_event_value(
            "-DOWNLOAD CSCA CERT AND CRL-",
            [True, "text_download_csca_crl_status", "OK", "green"],
        )

    if first_run:
        dsccrl_dir = Path(os.path.join(os.path.dirname(CSCA_certs_dir), Path("icao_pkd_dsccrl")))
        ml_dir = Path(os.path.join(os.path.dirname(CSCA_certs_dir), Path("icao_pkd_ml")))
        window.write_event_value(
            "-BUILD CERT STORE-",
            [True, "build_cert_store", "Building certificate store...", "white"],
        )
        build_store(CSCA_certs_dir, crls_dir, ml_dir, dsccrl_dir)
        window.write_event_value(
            "-BUILD CERT STORE-",
            [True, "build_cert_store_status", "OK", "green"],
        )

        # create face detector network
        if args.biometric:
            from emrtd_face_access.face_compare import opencv_dnn_detector

            opencv_dnn_detector()

    if args.mrz:
        window.write_event_value(
            "-SHOW DOCUMENT TO CAMERA-",
            [
                True,
                "text_instruction",
                "Please show the Machine Readable Zone (MRZ) of your document to the camera.",
                "white",
            ],
        )
        window.write_event_value(
            "-READ MRZ-",
            [True, "read_mrz", "Trying to capture MRZ information...", "white"],
        )
        mrz, mrz_image = capture_mrz(window, camera_id)

        document_number, birthdate, expiry_date, issuing_country, name, surname = parse_mrz_text(
            mrz
        )
        mrz_information = other_mrz(document_number, birthdate, expiry_date)
        window.write_event_value(
            "-WRITE NAME-",
            [True, "text_name_surname", f"NAME: {name} {surname}", "white"],
        )
        window.write_event_value(
            "-WRITE DOC NUM-",
            [True, "text_doc_num", f"DOCUMENT NUMBER: {document_number}", "white"],
        )
        window.write_event_value(
            "-READ MRZ-",
            [True, "read_mrz_status", "OK", "green"],
        )

    print("[?] Please place your document onto the card reader.")
    window.write_event_value(
        "-PLACE DOCUMENT-",
        [
            True,
            "text_instruction",
            "Please place your document onto the card reader.",
            "white",
        ],
    )
    window.write_event_value(
        "-WAIT FOR DOCUMENT-",
        [True, "text_card_insert", "Waiting for a document...", "white"],
    )
    sm_object = SMObject(wait_for_card())
    window.write_event_value("-PLACE DOCUMENT-", [True, "text_instruction", "", "white"])
    window.write_event_value(
        "-WAIT FOR DOCUMENT-",
        [True, "text_card_insert_status", "OK", "green"],
    )
    atr = sm_object.channel.getATR()

    print("[+] Card ATR: " + toHexString(atr))

    ## DERIVATION OF DOCUMENT BASIC ACCESS KEYS (KENC AND KMAC) ##
    if args.ee:
        try:
            (
                mrz_information,
                document_number,
                personal_id_code,
                name,
                surname,
            ) = estonia_read_mrz(sm_object)
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        else:
            issuing_country = "EST"
            window.write_event_value(
                "-WRITE NAME-",
                [True, "text_name_surname", f"NAME: {name} {surname}", "white"],
            )
            window.write_event_value(
                "-WRITE DOC NUM-",
                [True, "text_doc_num", f"DOCUMENT NUMBER: {document_number}", "white"],
            )
            window.write_event_value(
                "-WRITE ID CODE-",
                [True, "text_personal_code", f"PERSONAL ID CODE: {personal_id_code}", "white"],
            )
    if output_files:
        folder_name = create_output_folder(output_dir, document_number)

    if args.mrz and output_files:
        with open(os.path.join(folder_name, "mrz_text.txt"), "wt") as outfile:
            outfile.write("\n".join(mrz))

        mrz_image.save(os.path.join(folder_name, "mrz_photo.jpeg"))

    # Select eMRTD application
    print("[+] Selecting eMRTD Application ‘International AID’: A0000002471001...")
    aid = bytes.fromhex("A0000002471001")
    try:
        send(sm_object, APDU(b"\x00", b"\xA4", b"\x04", b"\x0C", Lc=nb(len(aid)), cdata=aid))
    except CardCommunicationError:
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    except CardConnectionException as ex:
        print(ex)
        window.write_event_value("-RAISED EXCEPTION-", "")
        return

    ## SECURE MESSAGING ##
    try:
        establish_bac_session_keys(sm_object, mrz_information.encode("utf-8"))
    except SessionKeyEstablishmentError as ex:
        print(ex)
        print("[-] Error while establishing BAC session keys")
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    except CardCommunicationError:
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    except CardConnectionException as ex:
        print(ex)
        window.write_event_value("-RAISED EXCEPTION-", "")
        return

    # Read EF.COM
    try:
        efcom = read_data_from_ef(window, sm_object, b"\x01\x1E", "EF.COM")
    except EFReadError as ex:
        print(ex)
        print("[-] Error while reading file EF.COM.")
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    except CardCommunicationError:
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    except CardConnectionException as ex:
        print(ex)
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    else:
        if output_files:
            with open(os.path.join(folder_name, "EF_COM.BIN"), "wb") as outfile:
                outfile.write(efcom)
        ef_com_dg_list = parse_efcom(efcom)

    # Read EF.SOD
    try:
        efsod = read_data_from_ef(window, sm_object, b"\x01\x1D", "EF.SOD")
    except EFReadError as ex:
        print(ex)
        print("[-] Error while reading file EF.SOD.")
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    except CardCommunicationError:
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    except CardConnectionException as ex:
        print(ex)
        window.write_event_value("-RAISED EXCEPTION-", "")
        return
    else:
        if output_files:
            with open(os.path.join(folder_name, "EF_SOD.BIN"), "wb") as outfile:
                outfile.write(efsod)

    window.write_event_value(
        "-PASSIVE AUTHENTICATION-",
        [True, "text_authentic", "Passive Authentication...", "white"],
    )
    pa_error = False
    ee_deviant_doc = False
    if issuing_country == "EST":
        try:
            with open(Path("certs/erpdeviationlist.bin"), "rb") as infile:
                deviation_docs = infile.read()
        except FileNotFoundError:
            pass
        else:
            if deviation_docs.find(document_number.encode("utf-8")) != -1:
                ee_deviant_doc = True
    try:
        passive_auth_return = passive_auth(efsod, ee_deviant_doc=ee_deviant_doc, dump=False)
    except PassiveAuthenticationCriticalError as ex:
        print(ex)
        window.write_event_value(
            "-PASSIVE AUTHENTICATION-",
            [False, "text_authentic_status", "ERROR", "red"],
        )
    else:
        if output_files:
            with open(os.path.join(folder_name, "CDS.der"), "wb") as outfile:
                outfile.write(passive_auth_return[2])
        if passive_auth_return[3] is None:
            pa_error = False
            hash_alg, data_group_hash_values, _, _ = passive_auth_return
        else:
            pa_error = True
            hash_alg, data_group_hash_values, _, exception = passive_auth_return
            print(exception)
            window.write_event_value(
                "-PASSIVE AUTHENTICATION-",
                [False, "text_authentic_status", "ERROR", "red"],
            )

    if atr in atr_exceptions and hash_alg == "sha256":
        hash_alg = "sha1"

    ef_sod_dg_list = get_dg_numbers(data_group_hash_values)

    if ef_com_dg_list != ef_sod_dg_list:
        print(
            "[-] EF.COM might have been changed, there are "
            "differences between EF_COM DGs and EF_SOD DGs!"
        )
        window.write_event_value(
            "-PASSIVE AUTHENTICATION-",
            [False, "text_authentic_status", "ERROR", "red"],
        )
        pa_error = True

    window.write_event_value(
        "-FILE VERIFICATION-",
        [True, "text_read_file", "Reading and verifying document files...", "white"],
    )

    file_read_error = False
    security_infos = []
    if b"\x0e" in ef_sod_dg_list:
        window.write_event_value(
            "-FILE VERIFICATION-",
            [True, "text_read_file_status", "EF.DG14", "yellow"],
        )
        try:
            DG = read_data_from_ef(window, sm_object, b"\x01" + b"\x0e", "EF.DG14")
        except EFReadError as ex:
            print(ex)
            print("[-] Error while reading file EF.DG14.")
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return

        if not assert_dg_hash(DG, data_group_hash_values, hash_alg, b"\x0e"):
            pa_error = True
            window.write_event_value(
                "-PASSIVE AUTHENTICATION-",
                [False, "text_authentic_status", "ERROR", "red"],
            )
            window.write_event_value(
                "-FILE VERIFICATION-",
                [False, "text_read_file_status", "EF.DG14", "red"],
            )
            file_read_error = True
        else:
            window.write_event_value(
                "-FILE VERIFICATION-",
                [True, "text_read_file_status", "EF.DG14", "green"],
            )
        security_infos = parse_security_infos(DG)
        window.write_event_value(
            "-CHIP AUTHENTICATION-",
            [True, "text_copied_2", "Chip Authentication...", "white"],
        )
        try:
            chip_auth(security_infos, sm_object)
        except ChipAuthenticationError as ex:
            print(ex)
            window.write_event_value(
                "-CHIP AUTHENTICATION-",
                [False, "text_copied_2_status", "ERROR", "red"],
            )
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        else:
            window.write_event_value(
                "-CHIP AUTHENTICATION-",
                [True, "text_copied_2_status", "OK", "green"],
            )

    if b"\x0f" in ef_sod_dg_list:
        window.write_event_value(
            "-FILE VERIFICATION-",
            [True, "text_read_file_status", "EF.DG15", "yellow"],
        )
        try:
            DG = read_data_from_ef(window, sm_object, b"\x01" + b"\x0f", "EF.DG15")
        except EFReadError as ex:
            print(ex)
            print("[-] Error while reading file EF.DG15.")
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return

        if output_files:
            with open(os.path.join(folder_name, "EF.DG15.BIN"), "wb") as outfile:
                outfile.write(DG)
        if not assert_dg_hash(DG, data_group_hash_values, hash_alg, b"\x0f"):
            pa_error = True
            window.write_event_value(
                "-PASSIVE AUTHENTICATION-",
                [False, "text_authentic_status", "ERROR", "red"],
            )
            window.write_event_value(
                "-FILE VERIFICATION-",
                [False, "text_read_file_status", "EF.DG15", "red"],
            )
            file_read_error = True
        else:
            window.write_event_value(
                "-FILE VERIFICATION-",
                [True, "text_read_file_status", "EF.DG15", "green"],
            )
        window.write_event_value(
            "-ACTIVE AUTHENTICATION-",
            [True, "text_copied_1", "Active Authentication...", "white"],
        )
        try:
            active_auth(DG, sm_object, security_infos)
        except ActiveAuthenticationError as ex:
            print(ex)
            window.write_event_value(
                "-ACTIVE AUTHENTICATION-",
                [False, "text_copied_1_status", "ERROR", "red"],
            )
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        else:
            window.write_event_value(
                "-ACTIVE AUTHENTICATION-",
                [True, "text_copied_1_status", "OK", "green"],
            )
    for dg, dgname in ef_sod_dg_list.items():
        if dg == b"\x0f" or dg == b"\x0e":
            # Active Authentication and Chip Authentication assumed completed
            continue

        if dg == b"\x03" or dg == b"\x04":
            # Sensitive Data: Finger and iris image data stored in the LDS
            # Data Groups 3 and 4, respectively. These data are considered
            # to be more privacy sensitive than data stored in the other
            # Data Groups.
            continue

        window.write_event_value(
            "-FILE VERIFICATION-",
            [True, "text_read_file_status", dgname, "yellow"],
        )
        try:
            DG = read_data_from_ef(window, sm_object, b"\x01" + dg, dgname)
        except EFReadError as ex:
            print(ex)
            print(f"[-] Error while reading file {dgname}.")
            if dg in [b"\x01", b"\x02"]:
                window.write_event_value("-RAISED EXCEPTION-", "")
                return
            continue
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return

        if output_files:
            with open(os.path.join(folder_name, dgname + ".BIN"), "wb") as outfile:
                outfile.write(DG)

        dg1_okay = True
        if not assert_dg_hash(DG, data_group_hash_values, hash_alg, dg):
            if dg == b"\x01":
                dg1_okay = False
            pa_error = True
            window.write_event_value(
                "-PASSIVE AUTHENTICATION-",
                [False, "text_authentic_status", "ERROR", "red"],
            )
            window.write_event_value(
                "-FILE VERIFICATION-",
                [False, "text_read_file_status", dgname, "red"],
            )
            file_read_error = True
        else:
            window.write_event_value(
                "-FILE VERIFICATION-",
                [True, "text_read_file_status", dgname, "green"],
            )

        if dg == b"\x02":
            id_image = get_jpeg_im(DG)
            window.write_event_value("-SHOW ID IMAGE-", [jpeg_to_png(id_image)])

        if dg == b"\x01":
            window.write_event_value(
                "-DOCUMENT EXPIRY CHECK-",
                [True, "document_expired", "Checking expiration status...", "white"],
            )
            mrz_read = get_dg1_content(DG)
            if dg1_okay:
                mrz_expiration_date = b""
                if len(mrz_read) == 90:
                    mrz_expiration_date = mrz_read[38:44]
                elif len(mrz_read) == 72:
                    mrz_expiration_date = mrz_read[57:63]
                elif len(mrz_read) == 88:
                    mrz_expiration_date = mrz_read[65:71]
                else:
                    print("[-] Error in MRZ that was read from DG1")
                    window.write_event_value(
                        "-DOCUMENT EXPIRY CHECK-",
                        [False, "document_expired_status", "ERROR", "red"],
                    )
                if mrz_expiration_date != b"":
                    valid = check_expiration(mrz_expiration_date)
                    if valid:
                        window.write_event_value(
                            "-DOCUMENT EXPIRY CHECK-",
                            [True, "document_expired_status", "OK", "green"],
                        )
                    else:
                        window.write_event_value(
                            "-DOCUMENT EXPIRY CHECK-",
                            [False, "document_expired_status", "EXPIRED", "red"],
                        )
            else:
                # Assume the document expired
                window.write_event_value(
                    "-DOCUMENT EXPIRY CHECK-",
                    [False, "document_expired_status", "ERROR", "red"],
                )

            if args.mrz:
                window.write_event_value(
                    "-MRZ COMPARE-",
                    [
                        True,
                        "text_mrz_compare",
                        "Comparing Machine Readable Zone with the DG1 inside the card...",
                        "white",
                    ],
                )
                mrz_scanned = str.encode("".join(mrz))
                if mrz_read != mrz_scanned:
                    print(
                        "[-] MRZ in DG1 doesn't match the MRZ read from the card!"
                        f"\nMRZ SCANNED:\n{mrz_scanned!s}\n\nMRZ READ:\n{mrz_read!s}"
                    )
                    window.write_event_value(
                        "-MRZ COMPARE-",
                        [
                            False,
                            "text_mrz_compare_status",
                            "ERROR",
                            "red",
                        ],
                    )
                else:
                    window.write_event_value(
                        "-MRZ COMPARE-",
                        [
                            True,
                            "text_mrz_compare_status",
                            "OK",
                            "green",
                        ],
                    )

            if db is not None:
                # Search MRZ in the db
                window.write_event_value(
                    "-CHECK DATABASE-",
                    [True, "check_database", "Checking database...", "white"],
                )
                database_obj = Query()
                if db.search(database_obj.mrz == "".join(mrz)) == []:
                    window.write_event_value(
                        "-CHECK DATABASE-",
                        [False, "check_database_status", "NOT FOUND", "red"],
                    )
                else:
                    window.write_event_value(
                        "-CHECK DATABASE-",
                        [True, "check_database_status", "OK", "green"],
                    )
            issuing_country = mrz_read[2:5]
            if issuing_country == b"EST":
                check_validity(window, document_number)

    if file_read_error:
        window.write_event_value(
            "-FILE VERIFICATION-",
            [False, "text_read_file_status", "ERROR", "red"],
        )
    else:
        window.write_event_value(
            "-FILE VERIFICATION-",
            [True, "text_read_file_status", "ALL OK", "green"],
        )

    if pa_error:
        window.write_event_value(
            "-PASSIVE AUTHENTICATION-",
            [False, "text_authentic_status", "ERROR", "red"],
        )
    else:
        window.write_event_value(
            "-PASSIVE AUTHENTICATION-",
            [True, "text_authentic_status", "OK", "green"],
        )

    if args.biometric:
        from emrtd_face_access.camera import capture_image
        from emrtd_face_access.face_compare import compare_faces
        from emrtd_face_access.image_operations import show_result

        print("[?] Please take a picture.")
        camera_image, face_location = capture_image(window, q, q2, lock2, camera_id)
        with lock:
            window.write_event_value(
                "-COMPARE RESULT-",
                [True, "text_face_compare", "Performing face comparison...", "white"],
            )
            comparison_result = compare_faces(
                id_image, camera_image, face_location, None if not output_files else folder_name
            )

            show_result(window, comparison_result)

            # termios.tcflush(sys.stdin, termios.TCIOFLUSH)
            # input("[?] Please take your ID card out and press [Enter] to run again.")
    window.write_event_value(
        "-TAKE ID OUT-",
        [
            True,
            "text_instruction",
            "Please take your document out and press [Enter] to run again.",
            "white",
        ],
    )
    window.write_event_value("-RUN COMPLETE-", "")
    return
