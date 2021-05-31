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
from emrtd_face_access.camera import continuous_cap


def parse_arguments() -> argparse.Namespace:
    """parse arguments"""

    def raise_(ex):
        """https://stackoverflow.com/a/8294654/6077951"""
        raise ex

    parser = argparse.ArgumentParser(
        description="Biometric (Facial) Access Control System Using ID Card"
    )

    parser.add_argument(
        "-online",
        action="store_true",
        help="Download crl and csca certificates online.",
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
    parser.add_argument(
        "--camera",
        "--c",
        default=-1,
        type=int,
        help="Device id of the camera to be used",
    )
    parser.add_argument(
        "--resolution",
        "--r",
        nargs=2,
        type=int,
        help="Resolution to be run at, if not given the screen resolution is used (width height)",
    )
    parser.add_argument(
        "--rotate",
        type=lambda x: int(x) if int(x) in (90, 180, 270) else raise_(ValueError(x)),
        default=0,
        help="Degrees to rotate clockwise (90, 180, 270)",
    )

    args = parser.parse_args()

    return args


def main_event_loop():
    """
    Main GUI event loop
    """
    args = parse_arguments()
    sg.theme("DarkBlack")
    w, h = sg.Window.get_screen_size()
    if args.resolution is not None:
        w, h = args.resolution
    layout = [[sg.Image(size=(w, h), key="camera_image")]]

    window = sg.Window(
        "eMRTD Face Access",
        layout,
        return_keyboard_events=True,
        use_default_focus=False,
        finalize=True,
        # no_titlebar=True,
        # keep_on_top=True,
        resizable=False,
        element_justification="center",
        margins=(0, 0),
    )
    window.maximize()
    window.set_cursor("none")

    first_run = True
    run = True
    q: Queue = Queue()
    threading.Thread(
        target=continuous_cap, args=(window, args.camera, w, h, args.rotate, q), daemon=True
    ).start()
    while True:
        if run:
            threading.Thread(target=main, args=(window, args, q, first_run), daemon=True).start()
            first_run = False
            run = False
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Exit"):
            q.put("Exit")
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

    while q.qsize() != 0:
        event, values = window.read(timeout=20)
        # pass

    # q.join()
    window.close()


if __name__ == "__main__":
    main_event_loop()
