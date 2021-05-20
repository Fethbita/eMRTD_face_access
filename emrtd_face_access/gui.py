#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Functions to create PySimpleGUI GUI layout"""

from typing import List, Union, Any, Dict
from queue import Queue
import threading

import PySimpleGUI as sg


def setup_gui(
    debug_on_gui: bool = True,
) -> List[List[Union[sg.Text, sg.Image, sg.Frame, sg.Button]]]:
    """Create GUI layout"""
    sg.theme("DarkTeal10")

    ts = (40, 1)
    status_ts = (12, 1)
    # fmt: off
    text = [
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_download_csca_crl"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_download_csca_crl_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="build_cert_store"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="build_cert_store_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="read_mrz"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="read_mrz_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="check_database"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="check_database_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_card_insert"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_card_insert_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_mrz_compare"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_mrz_compare_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="document_expired"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="document_expired_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_authentic"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_authentic_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_copied_1"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_copied_1_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_copied_2"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_copied_2_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_valid"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_valid_status"),
        ],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_read_file"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_read_file_status"),
        ],
        [sg.ProgressBar(1, orientation='h', size=(ts[0] + status_ts[0], 20), key='progress')],
        [
            sg.Text("", size=ts, justification="left", font="Helvetica 15", key="text_face_compare"),
            sg.Text("", size=status_ts, justification="right", font="Helvetica 15", key="text_face_compare_status"),
        ],
        [sg.Text("", size=ts, font="Helvetica 15")],
        [sg.Text("", size=ts, justification="center", font="Helvetica 15", key="result")],
    ]

    id_image = sg.Image(size=(240, 320), key="id_image")
    camera_image = sg.Image(size=(320, 240), key="camera_image")
    layout = [
        [sg.Text("", size=(85, 1), justification="center", font="Helvetica 15", key="text_instruction")],
        [sg.Text("NAME: ", size=(35, 1), justification="left", font="Helvetica 10", key="text_name_surname")],
        [sg.Text("DOCUMENT NUMBER: ", size=(35, 1), justification="left", font="Helvetica 10", key="text_doc_num")],
        [sg.Text("", size=(35, 1), justification="left", font="Helvetica 10", key="text_personal_code")],
        [id_image, camera_image, sg.Frame(layout=text, title="")],
        [sg.Button("Exit", size=(10, 1), font="Helvetica 14")],
    ]

    if debug_on_gui:
        layout += [[sg.Multiline(font="Courier 12", size=(100, 10), key="output_window", autoscroll=True,
                    auto_refresh=True, write_only=True, disabled=True, text_color="black")]]

    # fmt: on

    return layout


def reset_gui(window, debug_on_gui: bool = True):
    """Reset GUI layout"""
    text_elements = [
        "text_download_csca_crl",
        "text_download_csca_crl_status",
        "build_cert_store",
        "build_cert_store_status",
        "read_mrz",
        "read_mrz_status",
        "check_database",
        "check_database_status",
        "text_card_insert",
        "text_card_insert_status",
        "text_mrz_compare",
        "text_mrz_compare_status",
        "document_expired",
        "document_expired_status",
        "text_authentic",
        "text_authentic_status",
        "text_copied_1",
        "text_copied_1_status",
        "text_copied_2",
        "text_copied_2_status",
        "text_valid",
        "text_valid_status",
        "text_read_file",
        "text_read_file_status",
        "text_face_compare",
        "text_face_compare_status",
        "result",
        "text_instruction",
        "text_personal_code",
    ]

    for element in text_elements:
        window[element].update("", text_color="white")
    if debug_on_gui:
        window["output_window"].update("", text_color="black")
    window["text_name_surname"].update("NAME: ")
    window["text_doc_num"].update("DOCUMENT NUMBER: ")
    window["id_image"].update(filename="", size=(240, 320))
    window["camera_image"].update(filename="", size=(320, 240))
    window["progress"].update_bar(0, 1)


def camera_mode(
    window: sg.Window,
    q: Queue,
    q2: Queue,
    lock2: threading.Lock,
    event: str,
    values: Union[Dict[Any, Any]],
):
    """A new GUI loop for camera mode, wait for Enter and Escape buttons"""
    QT_ENTER_KEY1 = "special 16777220"
    QT_ENTER_KEY2 = "special 16777221"
    while True:
        event, values = window.read(timeout=20)
        if event in (sg.WIN_CLOSED, "Exit"):
            break
        if event == "-SHOW CAMERA-":
            window["camera_image"].update(data=values[event][0])
            nm_faces = values[event][1]
        if (
            event in values
            and isinstance(values[event], list)
            and isinstance(values[event][0], bool)
            and values[event][0]
        ):
            window[values[event][1]].update(values[event][2], text_color=values[event][3])
        elif (event in ("Return:36", "\r", QT_ENTER_KEY1, QT_ENTER_KEY2)) and nm_faces > 1:
            window["text_instruction"].update(
                "Multiple faces detected. Press [Enter] to try again", text_color="white"
            )
            # q.put("Pause")
            # try_again(window)
            # q.put("Continue")
        elif (event in ("Return:36", "\r", QT_ENTER_KEY1, QT_ENTER_KEY2)) and nm_faces < 1:
            window["text_instruction"].update(
                "No faces detected. Press [Enter] to try again", text_color="white"
            )
        elif (event in ("Return:36", "\r", QT_ENTER_KEY1, QT_ENTER_KEY2)) and nm_faces == 1:
            window["text_instruction"].update(
                "Press [Enter] to accept image, [Escape] to try again", text_color="white"
            )
            exit_outer_loop = False
            wait_for_signal = False
            while True:
                # The order of this if clause is important!
                if not wait_for_signal and lock2.acquire(False):
                    if accept_deny(window):
                        q.put("Done")
                        wait_for_signal = True
                        lock2.release()
                    else:
                        window["text_instruction"].update(
                            "Press [Enter] to capture image", text_color="white"
                        )
                        lock2.release()
                        break
                elif wait_for_signal and not q2.empty():
                    q2.get()
                    return
                event, values = window.read(timeout=20)
                if event in (sg.WIN_CLOSED, "Exit"):
                    exit_outer_loop = True
                    break
                if event == "-SHOW CAMERA-":
                    window["camera_image"].update(data=values[event][0])
                    nm_faces = values[event][1]

            if exit_outer_loop:
                break
    window.close()
    exit(0)


def try_again(window: sg.Window):
    """Press [Enter] to try again"""
    QT_ENTER_KEY1 = "special 16777220"
    QT_ENTER_KEY2 = "special 16777221"
    while True:
        event, _ = window.read(timeout=20)

        if event in (sg.WIN_CLOSED, "Exit"):
            break
        elif event in ("Return:36", "\r", QT_ENTER_KEY1, QT_ENTER_KEY2):
            return
    window.close()
    exit(0)


def accept_deny(window: sg.Window) -> bool:
    """Press [Enter] to accept image, [Escape] to try again"""
    QT_ENTER_KEY1 = "special 16777220"
    QT_ENTER_KEY2 = "special 16777221"
    while True:
        event, _ = window.read(timeout=20)

        if event in (sg.WIN_CLOSED, "Exit"):
            break
        elif event in ("Return:36", "\r", QT_ENTER_KEY1, QT_ENTER_KEY2):
            window["text_instruction"].update("", text_color="white")
            return True
        elif event.startswith("Escape"):
            return False
    window.close()
    exit(0)
