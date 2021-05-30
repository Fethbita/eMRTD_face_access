#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module has functions related to log files saved on disk"""

import os
from pathlib import Path


def create_output_folder(output_path: Path, document_number: str) -> Path:
    """
    Create an output directory for logs.
    The directory name is the document number.

    :returns: created folder name
    """
    folder_name = Path(os.path.join(output_path, document_number))
    if os.path.isdir(folder_name):
        i = 1
        folder_name_new = Path(os.path.join(output_path, f"{document_number} ({i})"))
        while os.path.isdir(folder_name_new):
            i += 1
            folder_name_new = Path(os.path.join(output_path, f"{document_number} ({i})"))
        folder_name = folder_name_new
    # Create folder if it doesn't exist
    os.makedirs(folder_name, exist_ok=True)

    return folder_name
