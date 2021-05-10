#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT


import threading

import PySimpleGUI as sg
from smartcard.Exceptions import CardConnectionException
from smartcard.util import toHexString

from emrtd_face_access.apdu import APDU
from emrtd_face_access.card_comms import send, wait_for_card, CardCommunicationError
from emrtd_face_access.ocr import capture_mrz
from emrtd_face_access.mrz import other_mrz, parse_mrz_text
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.bac import establish_bac_session_keys, SessionKeyEstablishmentError
from emrtd_face_access.file_operations import (
    EFReadError,
    read_data_from_ef,
    parse_efcom,
    parse_security_infos,
)
from emrtd_face_access.byte_operations import nb


def main():
    sg.theme("Black")

    # fmt: off
    layout = [
        [sg.Image(filename="", key="camera_image", )],
        [sg.Multiline(font="Courier 12", size=(80, 10), reroute_stderr=True, reroute_stdout=True,
        autoscroll=True, write_only=True, key="output_window", text_color="black", disabled=True, enter_submits=True)]]
    # fmt: on

    window = sg.Window(
        "Small demo in playground", layout, location=(800, 400), element_justification="c"
    )

    run = True
    # ---===--- Event LOOP Read and display frames, operate the GUI --- #
    while True:
        event, values = window.read(timeout=20)
        if event == sg.WIN_CLOSED:
            return

        elif event == "-SHOW MRZ-":
            window["camera_image"].update(data=values[event][0])

        elif event == "-HIDE MRZ-":
            window["camera_image"].update(filename="", size=(320, 240))

        elif event == "-RAISED EXCEPTION-":
            print("[!] Problem occured! Restarting...")
            run = True

        elif event == "-RESTART-":
            print("[!] Run completed! Restarting...")
            run = True

        if run:
            threading.Thread(target=program_logic, args=(window,), daemon=True).start()
            run = False


def program_logic(window: sg.Window):
    camera_id = -1
    mrz, _ = capture_mrz(window, camera_id)
    mrz_print = "\n".join(mrz)
    print(f"[i] MRZ Read:\n{mrz_print}")
    document_number, birthdate, expiry_date, issuing_country, name, surname = parse_mrz_text(mrz)
    mrz_information = other_mrz(document_number, birthdate, expiry_date)

    sm_object = SMObject(wait_for_card())

    atr = sm_object.channel.getATR()
    print("[+] Card ATR: " + toHexString(atr))

    # Select MF
    try:
        send(sm_object, APDU(b"\x00", b"\xA4", b"\x00", b"\x0C"))
    except CardCommunicationError:
        pass
    except CardConnectionException as ex:
        print(ex)
        pass
    else:
        print("[+] MF selected.")

    # Read EF.CardAccess
    ef_cardaccess = None
    try:
        ef_cardaccess = read_data_from_ef(window, sm_object, b"\x01\x1C", "EF.CardAccess")
    except EFReadError as ex:
        print(ex)
        print("[-] Error while reading file EF.CardAccess.")
        pass
    except CardCommunicationError:
        pass
    except CardConnectionException as ex:
        print(ex)
        pass
    else:
        # print(f"[i] EF.CardAccess Read: {toHexString(list(ef_cardaccess))}")
        security_infos_efca = parse_security_infos(ef_cardaccess)
        # pace(security_infos_efca, sm_object)

    # Read EF.DIR
    try:
        ef_dir = read_data_from_ef(window, sm_object, b"\x2F\x00", "EF.DIR")
    except EFReadError as ex:
        print(ex)
        print("[-] Error while reading file EF.DIR.")
    except CardCommunicationError:
        pass
    except CardConnectionException as ex:
        print(ex)
        pass
    else:
        print(f"[i] EF.DIR Read: {toHexString(list(ef_cardaccess))}")

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
        # print(f"[i] EF.COM Read: {toHexString(list(efcom))}")
        ef_com_dg_list = parse_efcom(efcom)
        print(f"[i] DGs specified in EF.COM: {list(ef_com_dg_list.values())}")

    # Read EF.DG14
    try:
        dg14 = read_data_from_ef(window, sm_object, b"\x01\x0E", "EF.DG14")
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
    else:
        # print(f"[i] EF.DG14 Read: {toHexString(list(dg14))}")
        security_infos_dg14 = parse_security_infos(dg14)
        for si in security_infos_efca:
            assert si in security_infos_dg14
            # print(dump_asn1(si))

    window.write_event_value("-RESTART-", "")
    return


# THE EXAMPLES ARE TAKEN FROM ICAO Doc 9303-11 App G-1
# pace([bytes.fromhex("3012060A04007F0007020204020202010202010D")], 42, 'T22000129364081251010318'.encode("utf-8"), "MRZ")
main()
