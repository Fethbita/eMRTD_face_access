#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module gets the JPEG image from DG2"""

import PySimpleGUI as sg


def get_jpeg_im(ef_dg2: bytes) -> bytes:
    """
    Get the JPEG imag from EF.DG2
    """
    # TODO ICAO9303-10 and ISO/IEC 19794-5
    im_start = ef_dg2.find(b"\xFF\xD8\xFF\xE0")
    if im_start == -1:
        im_start = ef_dg2.find(b"\x00\x00\x00\x0C\x6A\x50")
    image = ef_dg2[im_start:]

    return image


def show_result(window: sg.Window, result: bool) -> None:
    """
    Show the result as a file.
    """
    if result:
        window.write_event_value(
            "-COMPARE RESULT-",
            [True, "text_face_compare_status", "SUCCESS", "green"],
        )
    else:
        window.write_event_value(
            "-COMPARE RESULT-",
            [False, "text_face_compare_status", "FAILED", "red"],
        )
