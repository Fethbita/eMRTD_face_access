#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Try again prompt"""

import sys

# import termios


def proceed(message: str) -> bool:
    """
    Prints the given message
    returns True if the user still wants to proceed
    False otherwise.
    """
    print(message, file=sys.stderr)
    # termios.tcflush(sys.stdin, termios.TCIOFLUSH)
    # reply = input("[?] Do you still want to proceed? [y/N] ")
    # if reply.lower() != "y":
    #     return False
    return False
