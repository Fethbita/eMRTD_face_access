#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""APDU Class"""

from typing import Optional


class APDU:
    """APDU class\n
    cla: bytes\n
    ins: bytes\n
    p1: bytes\n
    p2: bytes\n
    Lc: Optional[bytes] = None\n
    cdata: Optional[bytes] = None\n
    Le: Optional[bytes] = None\n
    """

    cla: bytes
    ins: bytes
    p1: bytes
    p2: bytes
    Lc: Optional[bytes] = None
    cdata: Optional[bytes] = None
    Le: Optional[bytes] = None

    def __init__(
        self,
        cla: bytes,
        ins: bytes,
        p1: bytes,
        p2: bytes,
        Lc: Optional[bytes] = None,
        cdata: Optional[bytes] = None,
        Le: Optional[bytes] = None,
    ):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.Lc = Lc
        self.cdata = cdata
        self.Le = Le

        self._post_init()

    def _post_init(self):
        """Check for APDU bytes"""
        if len(self.cla) != 1 or len(self.ins) != 1 or len(self.p1) != 1 or len(self.p2) != 1:
            raise OverflowError("Cla, Ins, P1, P2 must be 1 byte")
        if self.Lc is not None and 1 != len(self.Lc) != 3:
            raise OverflowError("Lc must either be 1 byte or 3 bytes")
        if self.Le is not None and (
            (self.Lc is None and 1 != len(self.Le) != 3)
            or (self.Lc is not None and len(self.Lc) == 3 and len(self.Le) != 2)
        ):
            raise OverflowError("Le must either be 1 byte or 3 bytes or 2 bytes if Lc exists")

    def get_command_header(self) -> bytes:
        """return the command's header"""
        return self.cla + self.ins + self.p1 + self.p2
