#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module captures an image from the camera"""

from typing import List, Tuple
from queue import Queue
import threading

import copy
from cv2 import cv2
import numpy as np
import PySimpleGUI as sg

from emrtd_face_access.face_compare import get_bounding_boxes


def capture_image(
    window: sg.Window, q: Queue, q2: Queue, lock2: threading.Lock, camera_id: int
) -> Tuple[np.ndarray, List[Tuple[int, ...]]]:
    """
    Capture user image when pressed Enter

    :returns: opencv image
    """
    cap = cv2.VideoCapture(camera_id)

    window.write_event_value(
        "-CAMERA ON-",
        [True, "text_instruction", "Press [Enter] to capture image...", "white"],
    )
    pause = False
    while True:
        _, frame = cap.read()
        frame_shown = copy.deepcopy(frame)
        scale = 320 / frame_shown.shape[1]
        width = int(frame_shown.shape[1] * scale)
        height = int(frame_shown.shape[0] * scale)
        frame_shown = cv2.resize(frame_shown, (width, height))

        face_locations = get_bounding_boxes(frame, scale_size=(height, width))
        for (top, right, bottom, left) in face_locations:
            cv2.rectangle(frame_shown, (left, top), (right, bottom), (0, 255, 0), 2)

        imgbytes = cv2.imencode(".png", frame_shown)[1].tobytes()
        with lock2:
            if not q.empty():
                queue_element = q.get()
                if queue_element == "Done":
                    q2.put("Done")
                    break
                if queue_element == "Pause":
                    pause = True
                if queue_element == "Continue":
                    pause = False
            elif pause:
                continue
            else:
                window.write_event_value("-SHOW CAMERA-", [imgbytes, len(face_locations)])
                if len(face_locations) == 1:
                    frame_to_return = copy.deepcopy(frame)
                    face_locations_to_return = [tuple(int(x / scale) for x in face_locations[0])]

        # cv2.putText(
        #     frame_text,
        #     "Press [Enter] to capture image",
        #     (50, 50),
        #     cv2.FONT_HERSHEY_SIMPLEX,
        #     0.5,
        #     (0, 255, 255),
        #     1,
        #     cv2.LINE_4,
        # )

        # Display the resulting frame
        # cv2.imshow("frame", frame_text)

        # if cv2.waitKey(1) & 0xFF == ord("\r"):
        #     frame_question = frame.copy()
        #     cv2.putText(
        #         frame_question,
        #         "Press [Enter] to accept image, anything else to cancel",
        #         (50, 50),
        #         cv2.FONT_HERSHEY_SIMPLEX,
        #         0.5,
        #         (0, 255, 255),
        #         1,
        #         cv2.LINE_4,
        #     )
        #     cv2.imshow("frame", frame_question)

        #     if cv2.waitKey(0) & 0xFF == ord("\r"):
        #         break

    # When everything done, release the capture
    cap.release()
    # cv2.destroyAllWindows()

    return frame_to_return, face_locations_to_return
