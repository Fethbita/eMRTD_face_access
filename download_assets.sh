#!/bin/sh
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT


checksum=510ffd2471bd81e3fcc88a5beb4eae4fb445ccf8333ebc54e7302b83f4158a76
wget -q -P face_detection https://raw.githubusercontent.com/opencv/opencv_3rdparty/dnn_samples_face_detector_20180205_fp16/res10_300x300_ssd_iter_140000_fp16.caffemodel
sha256sum=$(sha256sum face_detection/res10_300x300_ssd_iter_140000_fp16.caffemodel)
if ! echo "$checksum face_detection/res10_300x300_ssd_iter_140000_fp16.caffemodel" | sha256sum -c -; then
    echo "Checksum failed for face_detection/res10_300x300_ssd_iter_140000_fp16.caffemodel" >&2
    rm -rf face_detection/res10_300x300_ssd_iter_140000_fp16.caffemodel
fi

checksum=dcd661dc48fc9de0a341db1f666a2164ea63a67265c7f779bc12d6b3f2fa67e9
wget -q -P face_detection https://raw.githubusercontent.com/opencv/opencv/master/samples/dnn/face_detector/deploy.prototxt
sha256sum=$(sha256sum face_detection/deploy.prototxt)
if ! echo "$checksum face_detection/deploy.prototxt" | sha256sum -c -; then
    echo "Checksum failed for face_detection/deploy.prototxt" >&2
    rm -rf face_detection/deploy.prototxt
fi
