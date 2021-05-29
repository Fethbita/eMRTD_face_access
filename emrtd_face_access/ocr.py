#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Functions related to OCR reading of MRZ"""

import copy
from typing import List, Tuple
from multiprocessing.pool import ThreadPool

from cv2 import cv2
import numpy as np
from PIL import Image
from tesserocr import PyTessBaseAPI, PSM
import PySimpleGUI as sg

from emrtd_face_access.mrz import parse_mrz_ocr


def capture_mrz(window: sg.Window, camera_id: int) -> Tuple[List[str], Image.Image]:
    """
    Capture the MRZ by using OCR and the camera footage.

    :returns: MRZ lines in a list
    """

    cap = cv2.VideoCapture(camera_id)

    tess_api = PyTessBaseAPI(init=False, psm=PSM.SINGLE_BLOCK_VERT_TEXT)
    tess_api.InitFull(
        # https://github.com/DoubangoTelecom/ultimateMRZ-SDK/tree/master/assets/models
        path="text_detection",
        lang="mrz",
        variables={
            "load_system_dawg": "false",
            "load_freq_dawg": "false",
            "tessedit_char_whitelist": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<",
        },
    )
    # mrz_list: List[List[str]] = []

    pool = ThreadPool(processes=1)
    ocr_running = False
    while True:
        _, frame = cap.read()

        mrz = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        mrz = cv2.adaptiveThreshold(mrz, 255, cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 21, 10)

        frame_shown = copy.deepcopy(mrz)
        width = 320
        height = int(frame_shown.shape[0] * (320 / frame_shown.shape[1]))
        frame_shown = cv2.resize(frame_shown, (width, height))

        alpha = 0.8
        frame_overlay = add_mrz_overlay(
            copy.deepcopy(frame_shown), "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", 3, 0.9, False
        )
        frame_overlay = add_mrz_overlay(
            frame_overlay, "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", 2, 0.9, True
        )
        cv2.addWeighted(frame_shown, alpha, frame_overlay, 1 - alpha, 0, frame_shown)

        imgbytes = cv2.imencode(".png", frame_shown)[1].tobytes()
        window.write_event_value("-SHOW MRZ-", [imgbytes])

        mrz = Image.fromarray(mrz)
        if not ocr_running:
            checked_frame = Image.fromarray(frame[:, :, ::-1])
            tess_api.SetImage(mrz)
            async_result = pool.apply_async(tess_api.GetUTF8Text)
            ocr_running = True

        if async_result.ready():
            ocr_running = False
            mrz_text = async_result.get()
            result = parse_mrz_ocr(mrz_text)

            if result is not None:
                break

    pool.terminate()
    # When everything done, release the capture
    cap.release()
    tess_api.End()

    window.write_event_value("-HIDE MRZ-", "")

    return (result, checked_frame)


def add_mrz_overlay(
    img: np.ndarray, text: str, times: int, width: float, bottom: bool = False
) -> np.ndarray:
    line_spacing = 1.5
    font = cv2.FONT_HERSHEY_SIMPLEX
    font_color = (0, 0, 0)
    line_type = 2
    text_width_s1, _ = cv2.getTextSize(text, font, 1, line_type)[0]
    font_scale = int(img.shape[1] * width) / text_width_s1
    text_width, text_height = cv2.getTextSize(text, font, font_scale, line_type)[0]
    if bottom:
        coords = (img.shape[1] - text_width) // 2, int(
            img.shape[0] - text_height * times * line_spacing
        )
    else:
        coords = (img.shape[1] - text_width) // 2, (img.shape[0] + text_height) // 2

    for i in range(times):
        cv2.putText(
            img,
            text,
            (coords[0], coords[1] + int(line_spacing * i * text_height)),
            font,
            font_scale,
            font_color,
            line_type,
        )

    return img
