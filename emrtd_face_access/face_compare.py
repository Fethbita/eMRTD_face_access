#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module does comparison of two images"""

import argparse
import os
from io import BytesIO
from typing import Union, List, Tuple
from pathlib import Path

import numpy as np
from PIL import Image
from cv2 import cv2
import face_recognition


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
    image: np.ndarray, conf_threshold: float = 0.5, scale_size: Tuple[int, int] = (-1, -1)
) -> List[Tuple[int, ...]]:
    """Image is expected in opencv format (BGR)
    takes image and returns face bounding boxes
    scale_size: Tuple[int, int] (height, width)"""
    # https://learnopencv.com/face-detection-opencv-dlib-and-deep-learning-c-python/
    net = opencv_dnn_detector()

    face_locations: List[Tuple[int, ...]] = []

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
    return face_locations


def compare_faces(
    id_image: bytes,
    cam_image: np.ndarray,
    face_location: List[Tuple[int, ...]],
    save_dest: Union[Path, None] = None,
) -> bool:
    """
    Compare two images. First one should be jpeg, the second one should be opencv image (numpy)
    face_location is the location of the face in the second image

    :returns: True if they are the same person, False otherwise.
    """
    im1 = bytes_to_np(id_image)
    im1 = im1[:, :, ::-1]
    id_face_loc = get_bounding_boxes(im1)
    im1 = im1[:, :, ::-1]
    face_encodings = face_recognition.face_encodings(im1, id_face_loc, 10, "large")[0]

    im2 = cam_image[:, :, ::-1]
    face_encodings2 = face_recognition.face_encodings(im2, face_location, 10, "large")[0]

    if save_dest:
        Image.fromarray(im1).save(os.path.join(save_dest, "face_one.jpeg"))
        Image.fromarray(im2).save(os.path.join(save_dest, "face_two.jpeg"))

    dist = face_recognition.face_distance([face_encodings], face_encodings2)[0]
    print("[i] Decision threshold is 0.5.")
    if dist <= 0.5:
        print(
            f"[+] Distance between the images is {dist}"
            "\n[+] These images are of the same people!"
        )
        return True
    else:
        print(
            f"[-] Distance between the images is {dist}\n"
            "[-] These images are of two different people!"
        )
        return False


def bytes_to_np(img: bytes) -> np.ndarray:
    """
    Converts bytes image (PIL) to numpy image (opencv)
    """
    im = Image.open(BytesIO(img))
    im = im.convert("RGB")
    return np.array(im)


def jpeg_to_png(img: bytes) -> bytes:
    """
    Converts a JPEG to a PNG
    """
    im = Image.open(BytesIO(img))
    width = 240
    height = int(im.size[1] * (240 / im.size[0]))
    im = im.convert("RGB").resize((width, height))
    stream = BytesIO()
    im.save(stream, format="PNG")
    return stream.getvalue()


def main(im1_filename: Path, im2_filename: Path) -> None:
    """
    Compare two persons images.
    """
    im1 = np.array(Image.open(im1_filename).convert("RGB"))
    im2 = np.array(Image.open(im2_filename).convert("RGB"))

    im1 = im1[:, :, ::-1]
    id_face_loc = get_bounding_boxes(im1)
    im1 = im1[:, :, ::-1]
    face_encodings = face_recognition.face_encodings(im1, id_face_loc, 10, "large")[0]

    im2 = im2[:, :, ::-1]
    cam_face_loc = get_bounding_boxes(im2)
    im2 = im2[:, :, ::-1]
    face_encodings2 = face_recognition.face_encodings(im2, cam_face_loc, 10, "large")[0]

    dist = face_recognition.face_distance([face_encodings], face_encodings2)[0]
    if dist < 0.5:
        print(f"[+] These images belong to the same person! ({dist})")
    else:
        print(f"[-] These images do not belong to the same person! ({dist})")


if __name__ == "__main__":

    def raise_(ex):
        """https://stackoverflow.com/a/8294654/6077951"""
        raise ex

    parser = argparse.ArgumentParser(description="Find if two images are of the same people.")
    parser.add_argument(
        "image_one",
        type=lambda x: x if os.path.isfile(x) else raise_(FileNotFoundError(x)),
        help="Path to image one",
    )
    parser.add_argument(
        "image_two",
        type=lambda x: x if os.path.isfile(x) else raise_(FileNotFoundError(x)),
        help="Path to image two",
    )
    args = parser.parse_args()

    main(Path(args.image_one), Path(args.image_two))
