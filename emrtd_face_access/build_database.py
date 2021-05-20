#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Build allowed documents database for emrtd_face_access"""

import argparse
import threading

import PySimpleGUI as sg
from smartcard.Exceptions import CardConnectionException
from smartcard.util import toHexString
from tinydb import TinyDB, Query

from emrtd_face_access.apdu import APDU
from emrtd_face_access.card_comms import send, wait_for_card, CardCommunicationError
from emrtd_face_access.ocr import capture_mrz
from emrtd_face_access.mrz import other_mrz, parse_mrz_text
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.bac import establish_bac_session_keys, SessionKeyEstablishmentError
from emrtd_face_access.file_operations import EFReadError, read_data_from_ef, get_dg1_content
from emrtd_face_access.byte_operations import nb
from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print


def parse_arguments() -> argparse.Namespace:
    """parse arguments"""
    parser = argparse.ArgumentParser(
        description="Build an allowed document database for emrtd_face_access"
    )

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-add", dest="insert", action="store_true", help="(default) Add a card to the database"
    )
    group.add_argument(
        "-delete", dest="insert", action="store_false", help="Remove a card from the database"
    )
    parser.set_defaults(insert=True)

    args = parser.parse_args()

    return args


def main_event_loop(args: argparse.Namespace, window: sg.Window):
    """
    Main GUI event loop
    """
    run = True

    db = TinyDB("db/db.json")

    while True:
        event, values = window.read(timeout=20)
        if event == sg.WIN_CLOSED:
            return

        elif event == "-SHOW WARNING-":
            if args.insert:
                if (
                    sg.popup_yes_no(
                        "Be aware that no security checks are made\n"
                        "This card MRZ will be added to the database if it does not already exist\n"
                        "Run the main program with this card before making sure that it is safe to add\n"
                        "Are you sure you want to add this card?"
                    )
                    == "Yes"
                ):
                    database_obj = Query()
                    if db.search(database_obj.mrz == values[event]) == []:
                        db.insert({"mrz": values[event]})
                        print("[+] Card is added to the database")
                    else:
                        print("[i] Card is already in the database")
                else:
                    print("[-] Card is NOT added to the database")
            else:
                if (
                    sg.popup_yes_no(
                        "Card is going to be removed from the database.\n" "Are you sure?"
                    )
                    == "Yes"
                ):
                    database_obj = Query()
                    if db.search(database_obj.mrz == values[event]) == []:
                        print("[-] Card is not in the database")
                    else:
                        db.remove(database_obj.mrz == values[event])
                        print("[+] Card is removed from the database")
                else:
                    print("[-] Card is NOT removed from the database")
            run = True
            print("[i] Restarting...")

        elif event == "-PROBLEM IN EITHER READ OR DOCUMENT-":
            sg.popup_ok(
                "Problem in either the MRZ scan or the document files\n"
                "Check the logs! Restarting..."
            )
            run = True

        elif event == "-SHOW MRZ-":
            window["camera_image"].update(data=values[event][0])

        elif event == "-HIDE MRZ-":
            window["camera_image"].update(filename="", size=(320, 240))

        elif event == "-RAISED EXCEPTION-":
            print("[!] Problem occured! Restarting...")
            run = True

        elif event == "-PRINT-":
            window["output_window"].print(values[event])

        if run:
            threading.Thread(target=database_builder_loop, args=(window,), daemon=True).start()
            run = False


def database_builder_loop(window: sg.Window):
    camera_id = -1
    mrz, _ = capture_mrz(window, camera_id)
    mrz_scan = "".join(mrz)
    print(f"[i] MRZ Read:\n{mrz_scan}")
    document_number, birthdate, expiry_date, _, _, _ = parse_mrz_text(mrz)
    mrz_information = other_mrz(document_number, birthdate, expiry_date)

    sm_object = SMObject(wait_for_card())

    atr = sm_object.channel.getATR()
    print("[+] Card ATR: " + toHexString(atr))

    # Select eMRTD Applet
    print("[+] Selecting LDS DF AID: A0000002471001...")
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

    # Read EF.DG1
    try:
        dg1 = read_data_from_ef(window, sm_object, b"\x01\x01", "EF.DG1")
    except EFReadError as ex:
        print(ex)
        print("[-] Error while reading file EF.DG1.")
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
        mrz_read = get_dg1_content(dg1).decode("utf-8")
        print(mrz_read)
        if mrz_read == mrz_scan:
            window.write_event_value("-SHOW WARNING-", mrz_read)
        else:
            window.write_event_value("-PROBLEM IN EITHER READ OR DOCUMENT-", "")


if __name__ == "__main__":
    a = parse_arguments()
    sg.theme("Black")

    # fmt: off
    layout = [
        [sg.Image(filename="", key="camera_image")],
        [sg.Multiline(font="Courier 12", size=(80, 10), key="output_window", autoscroll=True,
            auto_refresh=True, write_only=True, disabled=True, text_color="black")]]
    # fmt: on

    w = sg.Window("Database Builder", layout, location=(800, 400), element_justification="c")
    SetInterval().initialize(w, 0.1)
    SetInterval().start()
    main_event_loop(a, w)
    SetInterval().cancel()
    w.close()
