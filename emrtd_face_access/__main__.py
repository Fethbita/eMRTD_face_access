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

import PySimpleGUI as sg

from emrtd_face_access.main_program_loop import main
from emrtd_face_access.gui import setup_gui
from emrtd_face_access.print_to_sg import SetInterval
from emrtd_face_access.camera import continuous_cap

def parse_arguments() -> argparse.Namespace:
    """parse arguments"""
    parser = argparse.ArgumentParser(
        description="Biometric (Facial) Access Control System Using ID Card"
    )

    parser.add_argument(
        "-online",
        action="store_true",
        help="Download crl and csca certificates online.",
    )

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


def main_event_loop():
    """
    Main GUI event loop
    """
    args = parse_arguments()
    w, h = sg.Window.get_screen_size()
    layout = setup_gui(w, h)
    window = sg.Window(
        "eMRTD Face Access",
        layout,
        return_keyboard_events=True,
        use_default_focus=False,
        finalize=True,
        #no_titlebar=True,
        #keep_on_top=True,
        resizable=False,
        element_justification="center",

    )
    window.maximize()
    SetInterval().initialize(window, 0.1)
    SetInterval().start()

    first_run = True
    run = True
    q: Queue = Queue()
    threading.Thread(
        target=continuous_cap, args=(window, -1, w, h, q), daemon=True
    ).start()
    while True:
        if run:
            threading.Thread(
                target=main, args=(window, args, q, first_run), daemon=True
            ).start()
            first_run = False
            run = False
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Exit"):
            break
        elif event == "-RUN COMPLETE-":
            run = True
        elif event == "-RAISED EXCEPTION-":
            run = True
        elif event == "-SHOW CAMERA-":
            window["camera_image"].update(data=values[event])
        elif event == "-SHOW ID IMAGE-":
            window["id_image"].update(data=values[event][0])
        elif event == "-PROGRESS BAR-":
            window["progress"].update_bar(values[event][0], values[event][1])

    SetInterval().cancel()
    window.close()


if __name__ == "__main__":
    main_event_loop()
