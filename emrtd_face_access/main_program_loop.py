#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""The main program loop emrtd_face_access"""

import os

# import sys
# import termios
import argparse
from typing import Union, TextIO, BinaryIO
from pathlib import Path
from queue import Queue

import PySimpleGUI as sg
from smartcard.Exceptions import CardConnectionException
from smartcard.CardMonitoring import CardMonitor

from emrtd_face_access.apdu import APDU
from emrtd_face_access.card_comms import send, CardCommunicationError, CardWatcher
from emrtd_face_access.mrz import estonia_read_mrz, check_expiration
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
from emrtd_face_access.face_compare import opencv_dnn_detector
from emrtd_face_access.chip_authentication import chip_auth, ChipAuthenticationError
from emrtd_face_access.active_authentication import active_auth, ActiveAuthenticationError
from emrtd_face_access.image_operations import get_jpeg_im
from emrtd_face_access.ee_valid import check_validity, download_certs
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.log_operations import create_output_folder
from emrtd_face_access.icao_pkd_load import build_store
from emrtd_face_access.byte_operations import nb


# fmt: off
atr_exceptions = [
    # Estonian Identity Card (EstEID 3.0 contactless)
    [0x3B, 0x89, 0x80, 0x01, 0x4D, 0x54, 0x43, 0x4F, 0x53, 0x70, 0x02, 0x01, 0x05, 0x38],
    # Estonian Identity Card (EstEID 3.0 "JavaCard" cold)
    [0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0xA8],
    # Estonian Identity Card (EstEID 3.0 (18.01.2011) warm)
    [0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF],
]
# fmt: on


def main(
    window: sg.Window,
    args: argparse.Namespace,
    q: Queue,
    first_run: bool,
) -> None:
    """main function"""

    # Get dir arguments else fallback to EE certs
    CSCA_certs_dir = args.certs or Path("certs/csca_certs")
    crls_dir = args.certs or Path("certs/crls")
    output_dir = args.output
    output_files = not args.output is None
    outfile: Union[TextIO, BinaryIO]

    if (args.online and first_run) or (
        not os.path.isdir(CSCA_certs_dir) or not os.path.isdir(crls_dir)
    ):
        q.put([True, "text_download_csca_crl"])
        download_certs(CSCA_certs_dir, crls_dir)
        q.put([True, "text_download_csca_crl_status", "OK", "green"])

    if first_run:
        dsccrl_dir = Path(os.path.join(os.path.dirname(CSCA_certs_dir), Path("icao_pkd_dsccrl")))
        ml_dir = Path(os.path.join(os.path.dirname(CSCA_certs_dir), Path("icao_pkd_ml")))
        q.put([True, "build_cert_store"])
        build_store(CSCA_certs_dir, crls_dir, ml_dir, dsccrl_dir)
        q.put([True, "build_cert_store_status", "OK", "green"])

        # create face detector network
        opencv_dnn_detector()

    wait_for_card_event: Queue = Queue()
    cardmonitor = CardMonitor()
    cardobserver = CardWatcher(q, wait_for_card_event)
    cardmonitor.addObserver(cardobserver)

    # TODO
    # Show contact card connect gif here
    # TODO

    while True:
        print("[?] Please place your document onto the card reader.")
        q.put([True, "text_card_insert"])
        connection = wait_for_card_event.get()
        if connection[0] == "Valid card":
            sm_object = SMObject(connection[1])
            atr = connection[2]
            break
        elif connection[0] == "Known card":
            q.put(connection)
        elif connection[0] == "Unknown card":
            q.put(connection)

    q.put([True, "text_card_insert_status", "OK", "green"])

    ## DERIVATION OF DOCUMENT BASIC ACCESS KEYS (KENC AND KMAC) ##
    # From Estonian ID card applet
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
        issuing_country = b"EST"
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

    q.put([True, "text_authentic"])
    pa_error = False
    ee_deviant_doc = False
    if issuing_country == b"EST":
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
        q.put([False, "text_authentic_status", "ERROR", "red"])
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
            q.put([False, "text_authentic_status", "ERROR", "red"])

    if atr in atr_exceptions and hash_alg == "sha256":
        hash_alg = "sha1"

    ef_sod_dg_list = get_dg_numbers(data_group_hash_values)

    if ef_com_dg_list != ef_sod_dg_list:
        print(
            "[-] EF.COM might have been changed, there are "
            "differences between EF_COM DGs and EF_SOD DGs!"
        )
        q.put([False, "text_authentic_status", "ERROR", "red"])
        pa_error = True

    q.put([True, "text_read_file"])

    file_read_error = False
    security_infos = []
    if b"\x0e" in ef_sod_dg_list:
        q.put([True, "text_read_file_status", "EF.DG14", "yellow"])
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
            q.put([False, "text_authentic_status", "ERROR", "red"])
            q.put([False, "text_read_file_status", "EF.DG14", "red"])
            file_read_error = True
        else:
            q.put([True, "text_read_file_status", "EF.DG14", "green"])
        security_infos = parse_security_infos(DG)
        q.put([True, "text_copied_2"])
        try:
            chip_auth(security_infos, sm_object)
        except ChipAuthenticationError as ex:
            print(ex)
            q.put([False, "text_copied_2_status", "ERROR", "red"])
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        else:
            q.put([True, "text_copied_2_status", "OK", "green"])

    if b"\x0f" in ef_sod_dg_list:
        q.put([True, "text_read_file_status", "EF.DG15", "yellow"])
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
            q.put([False, "text_authentic_status", "ERROR", "red"])
            q.put([False, "text_read_file_status", "EF.DG15", "red"])
            file_read_error = True
        else:
            q.put([True, "text_read_file_status", "EF.DG15", "green"])
        q.put([True, "text_copied_1"])
        try:
            active_auth(DG, sm_object, security_infos)
        except ActiveAuthenticationError as ex:
            print(ex)
            q.put([False, "text_copied_1_status", "ERROR", "red"])
        except CardCommunicationError:
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        except CardConnectionException as ex:
            print(ex)
            window.write_event_value("-RAISED EXCEPTION-", "")
            return
        else:
            q.put([True, "text_copied_1_status", "OK", "green"])
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

        q.put([True, "text_read_file_status", dgname, "yellow"])
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
            q.put([False, "text_authentic_status", "ERROR", "red"])
            q.put([False, "text_read_file_status", dgname, "red"])
            file_read_error = True
        else:
            q.put([True, "text_read_file_status", dgname, "green"])

        if dg == b"\x02":
            id_image = get_jpeg_im(DG)
            q.put(["ID image", id_image])

        if dg == b"\x01":
            q.put([True, "document_expired"])
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
                    q.put([False, "document_expired_status", "ERROR", "red"])
                if mrz_expiration_date != b"":
                    valid = check_expiration(mrz_expiration_date)
                    if valid:
                        q.put([True, "document_expired_status", "OK", "green"])
                    else:
                        q.put([False, "document_expired_status", "EXPIRED", "red"])
            else:
                # Assume the document expired
                q.put([False, "document_expired_status", "ERROR", "red"])

            issuing_country = mrz_read[2:5]
            if issuing_country == b"EST":
                check_validity(q, document_number)

    if file_read_error:
        q.put([False, "text_read_file_status", "ERROR", "red"])
    else:
        q.put([True, "text_read_file_status", "ALL OK", "green"])

    if pa_error:
        q.put([False, "text_authentic_status", "ERROR", "red"])
    else:
        q.put([True, "text_authentic_status", "OK", "green"])

    # Wait for disconnect
    wait_for_card_event.get()

    window.write_event_value("-RUN COMPLETE-", "")
    return
