#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module captures an image from the camera"""

from typing import Dict, List, Tuple, Union
from queue import Queue
import time
import copy

import numpy as np
from cv2 import cv2
import PySimpleGUI as sg

from emrtd_face_access.face_compare import get_bounding_boxes, bytes_to_np
import face_recognition


def continuous_cap(
    window: sg.Window,
    camera_id: int,
    screen_width: int,
    screen_height: int,
    rotate: int,
    q: Queue,
) -> None:
    """
    Continuously capture
    """
    cap = cv2.VideoCapture(camera_id)
    # Disable autofocus
    cap.set(cv2.CAP_PROP_AUTOFOCUS, 0)
    font = cv2.FONT_HERSHEY_SIMPLEX
    line_type = 2
    _, frame = cap.read()
    if rotate == 90:
        frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
    elif rotate == 180:
        frame = cv2.rotate(frame, cv2.ROTATE_180)
    elif rotate == 270:
        frame = cv2.rotate(frame, cv2.ROTATE_90_COUNTERCLOCKWISE)
    text_alpha = 0.4
    ratio = min(screen_width / frame.shape[1], screen_height / frame.shape[0])
    width = int(frame.shape[1] * ratio)
    height = int(frame.shape[0] * ratio)
    # ratio = 0.2
    # width = screen_width
    # height = 500

    colors: Dict[str, Tuple[int, int, int]] = {
        "white": (0, 0, 0),
        "green": (0, 255, 0),
        "red": (0, 0, 255),
        "yellow": (0, 255, 255),
    }

    demos, append_axis = supported_card_images(screen_width, screen_height, width, height)

    (
        status_text,
        id_image,
        id_face_encoding,
        id_im_width,
        id_im_height,
        status_shown_time,
        error_text,
        error_text_coords,
        error_text_font_scale,
    ) = reset_camera_gui(height)

    max_text_width = 0
    for _, value in status_text.items():
        text_width, text_height = cv2.getTextSize(value[2], font, 1, line_type)[0]
        if text_width > max_text_width:
            max_text_width = text_width

    font_scale = int(width * 0.2) / max_text_width
    start_x_1 = width - int(width * 0.30)
    start_x_2 = width - int(width * 0.05)
    start_y = int(height * 0.05)

    while True:
        _, frame = cap.read()
        if rotate == 90:
            frame = cv2.rotate(frame, cv2.ROTATE_90_CLOCKWISE)
        elif rotate == 180:
            frame = cv2.rotate(frame, cv2.ROTATE_180)
        elif rotate == 270:
            frame = cv2.rotate(frame, cv2.ROTATE_90_COUNTERCLOCKWISE)
        frame_shown = copy.deepcopy(frame)
        frame_shown = cv2.resize(frame_shown, (width, height))

        if not q.qsize() == 0:
            queue_element = q.get()
            if isinstance(queue_element, list) and queue_element[0] == "ID image":
                id_image = bytes_to_np(queue_element[1])
                im1 = id_image[:, :, ::-1]
                id_face_loc = get_bounding_boxes(im1)
                id_face_encoding = face_recognition.face_encodings(
                    id_image, id_face_loc, 10, "large"
                )[0]
                id_image = im1
                ratio2 = (height * 0.3) / id_image.shape[0]
                id_im_width = int(id_image.shape[1] * ratio2)
                id_im_height = int(id_image.shape[0] * ratio2)
                id_image = cv2.resize(id_image, (id_im_width, id_im_height))

                status_shown_time = time.time()

            elif isinstance(queue_element, list) and queue_element[0] == "Unknown card":
                error_text = "Unrecognized card inserted."
                error_text_width, error_text_height = cv2.getTextSize(
                    error_text, font, 1, line_type
                )[0]
                error_text_font_scale = int(width * 0.9) / error_text_width
                error_text_width, error_text_height = cv2.getTextSize(
                    error_text, font, error_text_font_scale, line_type
                )[0]
                error_text_coords = (width - error_text_width) // 2, (
                    height + error_text_height
                ) // 2

            elif isinstance(queue_element, list) and queue_element[0] == "Known card":
                error_text = (
                    f"Your {queue_element[1]} is issued on {queue_element[2]} and is not supported."
                )
                error_text_width, error_text_height = cv2.getTextSize(
                    error_text, font, 1, line_type
                )[0]
                error_text_font_scale = int(width * 0.9) / error_text_width
                error_text_width, error_text_height = cv2.getTextSize(
                    error_text, font, error_text_font_scale, line_type
                )[0]
                error_text_coords = (width - error_text_width) // 2, (
                    height + error_text_height
                ) // 2

            elif (
                isinstance(queue_element, list)
                and isinstance(queue_element[0], bool)
                and len(queue_element) == 2
            ):
                if queue_element[1] in status_text:
                    status_text[queue_element[1]][1] = True

            elif (
                isinstance(queue_element, list)
                and isinstance(queue_element[0], bool)
                and len(queue_element) == 4
            ):
                if queue_element[1] in status_text:
                    status_text[queue_element[1]][1] = True
                    status_text[queue_element[1]][2] = queue_element[2]
                    status_text[queue_element[1]][3] = queue_element[3]

            elif queue_element == "Disconnect":
                (
                    status_text,
                    id_image,
                    id_face_encoding,
                    id_im_width,
                    id_im_height,
                    status_shown_time,
                    error_text,
                    error_text_coords,
                    error_text_font_scale,
                ) = reset_camera_gui(height)

            elif queue_element == "Exit":
                cap.release()
                q.task_done()
                return

            q.task_done()

        face_locations, face_locations_ns = get_bounding_boxes(
            frame, scale_size=(height, width), non_scaled=True
        )
        assert isinstance(face_locations, list)
        assert isinstance(face_locations_ns, list)
        if id_face_encoding is not None:
            cv2.addWeighted(
                id_image,
                0.5,
                frame_shown[height - id_im_height : height, :id_im_width, :],
                1 - 0.5,
                0,
                frame_shown[height - id_im_height : height, :id_im_width, :],
            )

            face_encodings = face_recognition.face_encodings(
                frame[:, :, ::-1], face_locations_ns, 1, "large"
            )
            distances = face_recognition.face_distance(face_encodings, id_face_encoding)
            for i in range(len(face_locations)):
                top, right, bottom, left = face_locations[i]
                if distances[i] <= 0.5:
                    cv2.rectangle(
                        frame_shown, (left, bottom - 35), (right, bottom), (0, 255, 0), cv2.FILLED
                    )
                    cv2.rectangle(frame_shown, (left, top), (right, bottom), (0, 255, 0), 2)
                else:
                    cv2.rectangle(
                        frame_shown, (left, bottom - 35), (right, bottom), (0, 0, 255), cv2.FILLED
                    )
                    cv2.rectangle(frame_shown, (left, top), (right, bottom), (0, 0, 255), 2)

                cv2.putText(
                    frame_shown,
                    str(round(distances[i], 4)),
                    (left + 6, bottom - 6),
                    cv2.FONT_HERSHEY_DUPLEX,
                    1.0,
                    (0, 0, 0),
                    1,
                )
        else:
            for (top, right, bottom, left) in face_locations:
                cv2.rectangle(frame_shown, (left, top), (right, bottom), (255, 255, 255), 2)

        if time.time() - status_shown_time <= 10 or status_shown_time == 0:
            i = 0
            frame_overlay = copy.deepcopy(frame_shown)
            cv2.rectangle(
                frame_overlay,
                (start_x_1, int(start_y - text_height)),
                (width, int(start_y + text_height * (len(status_text) / 2 - 1) * 1.5)),
                (255, 255, 255),
                cv2.FILLED,
            )
            for _, value in status_text.items():
                if value[1]:
                    if value[0] == "m":
                        coords = start_x_1, int(start_y + i * 1.5 * text_height)
                    elif value[0] == "s":
                        coords = start_x_2, int(start_y + i * 1.5 * text_height)
                    cv2.putText(
                        frame_overlay,
                        value[2],
                        coords,
                        cv2.FONT_HERSHEY_SIMPLEX,
                        font_scale,
                        colors[value[3]],
                        2,
                    )
                if value[0] == "s":
                    i += 1
            cv2.addWeighted(frame_shown, 1 - text_alpha, frame_overlay, text_alpha, 0, frame_shown)
            frame_shown = np.concatenate((frame_shown, demos), axis=append_axis)

        if error_text != "":
            frame_overlay = copy.deepcopy(frame_shown)
            cv2.rectangle(
                frame_overlay,
                error_text_coords,
                (error_text_coords[0] + error_text_width, error_text_coords[1] - error_text_height),
                (0, 0, 0),
                cv2.FILLED,
            )
            cv2.putText(
                frame_overlay,
                error_text,
                error_text_coords,
                cv2.FONT_HERSHEY_SIMPLEX,
                error_text_font_scale,
                colors["red"],
                2,
            )
            cv2.addWeighted(frame_shown, 1 - 0.6, frame_overlay, 0.6, 0, frame_shown)

        imgbytes = cv2.imencode(".png", frame_shown)[1].tobytes()
        window.write_event_value("-SHOW CAMERA-", imgbytes)


def reset_camera_gui(
    cam_height: int,
) -> Tuple[
    Dict[str, List[Union[str, bool]]],
    np.ndarray,
    List[float],
    int,
    int,
    float,
    str,
    Tuple[int, int],
    int,
]:
    status_text: Dict[str, List[Union[str, bool]]] = {
        # "text_download_csca_crl": ["m", False, "Downloading CSCA certificates and CRLs...", "white"],
        # "text_download_csca_crl_status": ["s", False, "", ""],
        # "build_cert_store": ["m", False, "Building certificate store...", "white"],
        # "build_cert_store_status": ["s", False, "", ""],
        # "read_mrz": [False],
        # "read_mrz_status": [False],
        # "check_database": [False],
        # "check_database_status": [False],
        "text_card_insert": ["m", False, "Waiting for a document...", "white"],
        "text_card_insert_status": ["s", False, "", ""],
        # "text_mrz_compare": [False],
        # "text_mrz_compare_status": [False],
        "document_expired": ["m", False, "Checking expiration status...", "white"],
        "document_expired_status": ["s", False, "", ""],
        "text_authentic": ["m", False, "Passive Authentication...", "white"],
        "text_authentic_status": ["s", False, "", ""],
        "text_copied_1": ["m", False, "Active Authentication...", "white"],
        "text_copied_1_status": ["s", False, "", ""],
        "text_copied_2": ["m", False, "Chip Authentication...", "white"],
        "text_copied_2_status": ["s", False, "", ""],
        "text_valid": ["m", False, "Performing online document validity check...", "white"],
        "text_valid_status": ["s", False, "", ""],
        "text_read_file": ["m", False, "Reading and verifying document files...", "white"],
        "text_read_file_status": ["s", False, "", ""],
    }
    if (
        "id_image" in reset_camera_gui.__dict__
        and "id_face_encoding" in reset_camera_gui.__dict__
        and "id_im_width" in reset_camera_gui.__dict__
        and "id_im_height" in reset_camera_gui.__dict__
        and "status_shown_time" in reset_camera_gui.__dict__
        and "cam_height" in reset_camera_gui.__dict__
        and reset_camera_gui.cam_height == cam_height
    ):
        return (
            status_text,
            reset_camera_gui.id_image,
            reset_camera_gui.id_face_encoding,
            reset_camera_gui.id_im_width,
            reset_camera_gui.id_im_height,
            reset_camera_gui.status_shown_time,
            "",
            (0, 0),
            0,
        )
    else:
        reset_camera_gui.cam_height = cam_height

        id_image = cv2.imread("face_detection/jaak-kristjan.jpg")
        # crop only the facial image
        id_image = id_image[15:1087, 15:1079, ::]

        id_face_loc = get_bounding_boxes(id_image)
        reset_camera_gui.id_face_encoding = face_recognition.face_encodings(
            id_image[:, :, ::-1], id_face_loc, 10, "large"
        )[0]

        ratio2 = (cam_height * 0.3) / id_image.shape[0]
        reset_camera_gui.id_im_width = int(id_image.shape[1] * ratio2)
        reset_camera_gui.id_im_height = int(id_image.shape[0] * ratio2)
        reset_camera_gui.id_image = cv2.resize(
            id_image, (reset_camera_gui.id_im_width, reset_camera_gui.id_im_height)
        )

        reset_camera_gui.status_shown_time = 0.0

        return (
            status_text,
            reset_camera_gui.id_image,
            reset_camera_gui.id_face_encoding,
            reset_camera_gui.id_im_width,
            reset_camera_gui.id_im_height,
            reset_camera_gui.status_shown_time,
            "",
            (0, 0),
            0,
        )


def supported_card_images(
    screen_width: int, screen_height: int, width: int, height: int
) -> Tuple[np.ndarray, int]:
    trp_2018 = cv2.imread("docs/demo_rp_2018_12_03.jpg")
    trp_2020 = cv2.imread("docs/demo_rp_2020_10_01.jpg")
    id_2021 = cv2.imread("docs/demo_id_2021_07.jpg")
    border_color = [255, 255, 255]
    if width != screen_width:
        cards_width = screen_width - width

        card_ratio = cards_width / trp_2018.shape[1]
        cards_height = int(trp_2018.shape[0] * card_ratio)

        if cards_height * 3 >= screen_height:
            border_height = 50
            last_border_height = 50
            cards_height = int(height // 3) - border_height
            card_ratio = cards_height / trp_2018.shape[0]
            cards_width = int(trp_2018.shape[1] * card_ratio)
        else:
            border_height = int((screen_height - cards_height * 3) / 3)
            last_border_height = height - (cards_height * 3 + 3 * border_height)
            last_border_height += border_height

        trp_2018 = cv2.resize(trp_2018, (cards_width, cards_height))
        trp_2020 = cv2.resize(trp_2020, (cards_width, cards_height))
        id_2021 = cv2.resize(id_2021, (cards_width, cards_height))

        append_axis = 1

    elif height != screen_height:
        border_height = 50
        last_border_height = border_height
        cards_height = screen_height - height - border_height
        card_ratio = (cards_height) / trp_2018.shape[0]
        cards_width = int(trp_2018.shape[1] * card_ratio)

        if cards_width * 3 >= screen_width:
            cards_width = int(width // 3)
            card_ratio = cards_width / trp_2018.shape[1]
            cards_height = int(trp_2018.shape[0] * card_ratio)
            border_height = screen_height - height - cards_height
            last_border_height = border_height

        trp_2018 = cv2.resize(trp_2018, (cards_width, cards_height))
        trp_2020 = cv2.resize(trp_2020, (cards_width, cards_height))
        id_2021 = cv2.resize(id_2021, (cards_width, cards_height))

        append_axis = 0

    trp_2018 = cv2.copyMakeBorder(
        trp_2018,
        0,
        border_height,
        0,
        0,
        cv2.BORDER_CONSTANT,
        value=border_color,
    )

    text = f"Residence permit cards issued since December 2018 are supported"
    text_width, _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, 1, 2)[0]
    text_font_scale = int(cards_width * 0.9) / text_width
    text_width, text_height = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, text_font_scale, 2)[0]
    text_coords = (cards_width - text_width) // 2, cards_height + (
        (border_height + text_height) // 2
    )

    cv2.putText(
        trp_2018,
        text,
        text_coords,
        cv2.FONT_HERSHEY_SIMPLEX,
        text_font_scale,
        (0, 0, 0),
        2,
    )

    trp_2020 = cv2.copyMakeBorder(
        trp_2020,
        0,
        border_height,
        0,
        0,
        cv2.BORDER_CONSTANT,
        value=border_color,
    )

    text = f"Residence permit cards issued since October 2020 are supported"
    text_width, _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, 1, 2)[0]
    text_font_scale = int(cards_width * 0.9) / text_width
    text_width, text_height = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, text_font_scale, 2)[0]
    text_coords = (cards_width - text_width) // 2, cards_height + (
        (border_height + text_height) // 2
    )

    cv2.putText(
        trp_2020,
        text,
        text_coords,
        cv2.FONT_HERSHEY_SIMPLEX,
        text_font_scale,
        (0, 0, 0),
        2,
    )

    id_2021 = cv2.copyMakeBorder(
        id_2021,
        0,
        last_border_height,
        0,
        0,
        cv2.BORDER_CONSTANT,
        value=border_color,
    )
    text = f"ID cards issued since July 2021 are supported"
    text_width, _ = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, 1, 2)[0]
    text_font_scale = int(cards_width * 0.9) / text_width
    text_width, text_height = cv2.getTextSize(text, cv2.FONT_HERSHEY_SIMPLEX, text_font_scale, 2)[0]
    text_coords = (cards_width - text_width) // 2, cards_height + (
        (last_border_height + text_height) // 2
    )

    cv2.putText(
        id_2021,
        text,
        text_coords,
        cv2.FONT_HERSHEY_SIMPLEX,
        text_font_scale,
        (0, 0, 0),
        2,
    )

    if width != screen_width:
        demos = np.concatenate((trp_2018, trp_2020, id_2021), axis=0)
    elif height != screen_height:
        demos = np.concatenate((trp_2018, trp_2020, id_2021), axis=1)

    return demos, append_axis
