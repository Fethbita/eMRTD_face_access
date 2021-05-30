#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Functions to create PySimpleGUI GUI layout"""

from typing import List, Union

import PySimpleGUI as sg


def setup_gui(width: int, height: int) -> List[List[Union[sg.Text, sg.Image, sg.Frame, sg.Button]]]:
    """Create GUI layout"""
    sg.theme("DarkBlack")

    camera_image = sg.Image(size=(width, height), key="camera_image")
    layout = [[sg.Button("Exit", size=(10, 1), font="Helvetica 14")], [camera_image]]

    return layout
