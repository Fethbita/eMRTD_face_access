#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module does comparison of two images"""

from io import BytesIO
from typing import List, Tuple, Union

import numpy as np
from PIL import Image
from cv2 import cv2


def opencv_dnn_detector() -> cv2.dnn_Net:
    """Create face detection network"""
    if "net" in opencv_dnn_detector.__dict__:
        return opencv_dnn_detector.net

    print("[+] Creating face detector network...")
    # downloaded from
    # https://raw.githubusercontent.com/opencv/opencv_3rdparty/dnn_samples_face_detector_20180205_fp16/res10_300x300_ssd_iter_140000_fp16.caffemodel
    model_file = "face_detection/res10_300x300_ssd_iter_140000_fp16.caffemodel"
    # downloaded from
    # https://raw.githubusercontent.com/opencv/opencv/master/samples/dnn/face_detector/deploy.prototxt
    config_file = "face_detection/deploy.prototxt"
    opencv_dnn_detector.net = cv2.dnn.readNetFromCaffe(config_file, model_file)
    return opencv_dnn_detector.net


def get_bounding_boxes(
    image: np.ndarray,
    conf_threshold: float = 0.5,
    scale_size: Tuple[int, int] = (-1, -1),
    non_scaled: bool = False,
) -> Union[List[Tuple[int, ...]], Tuple[List[Tuple[int, ...]], List[Tuple[int, ...]]]]:
    """Image is expected in opencv format (BGR)
    takes image and returns face bounding boxes
    scale_size: Tuple[int, int] (height, width)"""
    # https://learnopencv.com/face-detection-opencv-dlib-and-deep-learning-c-python/
    net = opencv_dnn_detector()

    face_locations: List[Tuple[int, ...]] = []

    if non_scaled:
        face_locations2: List[Tuple[int, ...]] = []

    blob = cv2.dnn.blobFromImage(image, 1.0, (300, 300), [104, 117, 123], False, False)
    net.setInput(blob)
    detections = net.forward()
    for i in range(detections.shape[2]):
        confidence = detections[0, 0, i, 2]
        if confidence > conf_threshold:
            x1 = detections[0, 0, i, 3]
            y1 = detections[0, 0, i, 4]
            x2 = detections[0, 0, i, 5]
            y2 = detections[0, 0, i, 6]
            if non_scaled:
                x1_ns = int(x1 * image.shape[1])
                y1_ns = int(y1 * image.shape[0])
                x2_ns = int(x2 * image.shape[1])
                y2_ns = int(y2 * image.shape[0])
                face_locations2.append((y1_ns, x2_ns, y2_ns, x1_ns))
            if scale_size == (-1, -1):
                x1 = int(x1 * image.shape[1])
                y1 = int(y1 * image.shape[0])
                x2 = int(x2 * image.shape[1])
                y2 = int(y2 * image.shape[0])
            else:
                x1 = int(x1 * scale_size[1])
                y1 = int(y1 * scale_size[0])
                x2 = int(x2 * scale_size[1])
                y2 = int(y2 * scale_size[0])
            face_locations.append((y1, x2, y2, x1))
    if non_scaled:
        return face_locations, face_locations2
    return face_locations


def bytes_to_np(img: bytes) -> np.ndarray:
    """
    Converts bytes image (PIL) to numpy image (opencv)
    """
    im = Image.open(BytesIO(img))
    im = im.convert("RGB")
    return np.array(im)
