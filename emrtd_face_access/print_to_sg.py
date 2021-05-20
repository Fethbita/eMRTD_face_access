#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Print to sg Multiline and the terminal"""

import threading
import time
from io import StringIO

import PySimpleGUI as sg


# https://stackoverflow.com/a/6798042/6077951
class _Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(_Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# https://stackoverflow.com/a/48709380/6077951
class SetInterval(metaclass=_Singleton):
    def __init__(self):
        self.window = None # call initialize to set
        self.interval = 0  # call initialize to set
        self.stop_event = threading.Event()
        self.buffer = StringIO()

    def start(self):
        thread = threading.Thread(target=self.__set_interval)
        thread.start()

    def cancel(self):
        self.stop_event.set()

    def initialize(self, window: sg.Window, interval: float):
        self.window = window
        self.interval = interval

    def __set_interval(self):
        next_time = time.time() + self.interval
        while not self.stop_event.wait(next_time - time.time()):
            next_time += self.interval
            self.print_sg()

    def print(self, *args, **kwargs):
        if not self.stop_event.is_set():
            print(*args, **kwargs)
            print(*args, **kwargs, file=self.buffer)

    def print_sg(self):
        if self.window.was_closed():
            self.cancel()
        else:
            output = self.buffer.getvalue()
            if len(output) != 0:
                self.window.write_event_value("-PRINT-", output[:-1])
                self.buffer.close()
                self.buffer = StringIO()
