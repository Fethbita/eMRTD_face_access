#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""The entry point for emrtd_face_access which includes the GUI event loop"""

import os
import argparse
from pathlib import Path
import threading
from queue import Queue
from typing import Optional

import PySimpleGUI as sg
from tinydb import TinyDB

from emrtd_face_access.main_program_loop import main
from emrtd_face_access.gui import setup_gui, reset_gui
from emrtd_face_access.gui import camera_mode, try_again


def parse_arguments() -> argparse.Namespace:
    """parse arguments"""
    parser = argparse.ArgumentParser(
        description="Biometric (Facial) Access Control System Using ID Card"
    )

    parser.add_argument(
        "-no-debug",
        action="store_true",
        help="Disable debug panel and print logging information on stdout.",
    )

    parser.add_argument(
        "-online",
        action="store_true",
        help="Download crl and csca certificates online.",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-ee", action="store_true", help="Estonian id card/passport")
    group.add_argument("-mrz", action="store_true", help="MRZ info will be given")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-bio",
        dest="biometric",
        action="store_true",
        help="(default) Use biometric control (facial recognition)",
    )
    group.add_argument(
        "-no-bio",
        dest="biometric",
        action="store_false",
        help="Do not use biometric control (facial recognition)",
    )
    parser.set_defaults(biometric=True)

    def raise_(ex):
        """https://stackoverflow.com/a/8294654/6077951"""
        raise ex

    parser.add_argument(
        "--db",
        type=lambda x: Path(x) if os.path.isfile(x) else raise_(FileNotFoundError(x)),
        help="Database to be used for controlling",
    )
    parser.add_argument(
        "--certs",
        type=lambda x: Path(x) if os.path.isdir(x) else raise_(NotADirectoryError(x)),
        help="Directory to CSCA certificates",
    )
    parser.add_argument(
        "--crls",
        type=lambda x: Path(x) if os.path.isdir(x) else raise_(NotADirectoryError(x)),
        help="Directory to certificate revocation lists",
    )
    parser.add_argument(
        "--output",
        "--o",
        type=lambda x: Path(x) if os.path.isdir(x) else raise_(NotADirectoryError(x)),
        help="Directory to save read card files",
    )

    args = parser.parse_args()

    return args


def main_event_loop(args: argparse.Namespace, window: sg.Window, db: Optional[TinyDB]):
    """
    Main GUI event loop
    """
    first_run = True
    run = True
    everything_ok: bool
    q: Queue = Queue()
    q2: Queue = Queue()
    lock = threading.Lock()
    lock2 = threading.Lock()
    while True:
        event, values = window.read(timeout=20)
        if event in (sg.WIN_CLOSED, "Exit"):
            return
        elif event == "-RUN COMPLETE-":
            if everything_ok:
                window["result"].update("ACCESS GRANTED", text_color="green")
            else:
                window["result"].update("ACCESS DENIED", text_color="red")
            run = True
            try_again(window)
            reset_gui(window, debug_on_gui=not a.no_debug)
        elif event == "-RAISED EXCEPTION-":
            everything_ok = False
            window["text_instruction"].update(
                "PROBLEM OCCURED (CHECK LOGS)! Press [Enter] to start over!", text_color="red"
            )
            run = True
            try_again(window)
            reset_gui(window, debug_on_gui=not a.no_debug)
        elif event == "-SHOW CAMERA-":
            with lock:
                camera_mode(window, q, q2, lock2, event, values)
        elif event == "-SHOW MRZ-":
            window["camera_image"].update(data=values[event][0])
        elif event == "-HIDE MRZ-":
            window["camera_image"].update(filename="", size=(320, 240))
        elif event == "-SHOW ID IMAGE-":
            window["id_image"].update(data=values[event][0])
        elif event == "-PROGRESS BAR-":
            window["progress"].update_bar(values[event][0], values[event][1])
        elif (
            event in values
            and isinstance(values[event], list)
            and isinstance(values[event][0], bool)
        ):
            window[values[event][1]].update(values[event][2], text_color=values[event][3])
            if not values[event][0]:
                everything_ok = False
        if run:
            everything_ok = True
            threading.Thread(
                target=main,
                args=(
                    window,
                    args,
                    db,
                    q,
                    q2,
                    lock,
                    lock2,
                    first_run,
                ),
                daemon=True,
            ).start()
            first_run = False
            run = False


if __name__ == "__main__":
    a = parse_arguments()
    layout = setup_gui(debug_on_gui=not a.no_debug)
    w = sg.Window(
        "eMRTD Face Access",
        layout,
        return_keyboard_events=True,
        use_default_focus=False,
    )
    d = None
    if a.db:
        d = TinyDB(a.db)
    main_event_loop(a, w, d)
    w.close()
