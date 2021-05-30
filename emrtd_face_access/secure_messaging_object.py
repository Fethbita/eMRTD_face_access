#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Secure Messaging Object class module"""

from typing import Optional

from smartcard.CardConnectionDecorator import CardConnectionDecorator


class SMObject:
    """Class for keeping track of secure messaging parameters."""

    channel: CardConnectionDecorator
    _enc_alg: Optional[str] = None  # choice ("3DES", "AES")
    _mac_alg: Optional[str] = None  # choice ("DES", "AES-CMAC")
    pad_len: int = 0
    ks_enc: Optional[bytes] = None
    ks_mac: Optional[bytes] = None
    ssc: Optional[bytes] = None

    def __init__(self, channel: CardConnectionDecorator) -> None:
        self.channel = channel

    def increment_ssc(self):
        """Increments SSC by one"""
        length = len(self.ssc)
        int_val = int.from_bytes(self.ssc, byteorder="big")
        int_val += 1
        self.ssc = int_val.to_bytes(length, byteorder="big")

    # def decrement_SSC(self):
    #     length = len(self.ssc)
    #     int_val = int.from_bytes(self.ssc, byteorder="big")
    #     int_val -= 1
    #     self.ssc = int_val.to_bytes(length, byteorder="big")

    @property
    def enc_alg(self):
        return self._enc_alg

    @enc_alg.setter
    def enc_alg(self, value):
        if value not in ["3DES", "AES"]:
            raise ValueError("[-] Only '3DES' and 'AES' are allowed for encryption algorithm")
        self._enc_alg = value

    @property
    def mac_alg(self):
        return self._mac_alg

    @mac_alg.setter
    def mac_alg(self, value):
        if value not in ["DES", "AES-CMAC"]:
            raise ValueError("[-] Only 'DES' and 'AES-CMAC' are allowed for mac algorithm")
        self._mac_alg = value
