#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module operations on bytes objects"""

from typing import Union


def nb(i: int, length: Union[int, bool] = False) -> bytes:
    """converts integer to bytes"""
    b = b""
    if length is False:
        length = (i.bit_length() + 7) // 8
    for _ in range(length):
        b = bytes([i & 0xFF]) + b
        i >>= 8
    return b


def padding_method_2(data: bytes, pad_to: int) -> bytes:
    """
    Pads data to n blocks using ISO/IEC 9797-1 Padding method 2
    """
    data = data + bytes([0x80])
    if len(data) % pad_to != 0:
        data = data + bytes([0] * (pad_to - (len(data)) % pad_to))
    return data


def remove_padding(data: bytes) -> bytes:
    """
    Removes ISO/IEC 9797-1 Padding method 2 from data
    """
    for idx, b in enumerate(reversed(data), start=1):
        if b == 0x80:
            return data[: len(data) - idx]
    return b""
