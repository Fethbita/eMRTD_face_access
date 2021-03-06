#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Module for Estonian ID card related functions"""

import os
from pathlib import Path
from urllib import request
import subprocess

import PySimpleGUI as sg

from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print


def check_validity(window: sg.Window, doc_num: str) -> None:
    """
    For Estonian documents, check the validity on "https://www2.politsei.ee/qr/?qr=" website
    """
    window.write_event_value(
        "-ONLINE CHECK FOR EST-",
        [True, "text_valid", "Performing online document validity check...", "white"],
    )
    page = request.urlopen("https://www2.politsei.ee/qr/?qr=" + doc_num).read().decode("utf8")
    if f"The document {doc_num} is valid." in page:
        print(f"[+] The document {doc_num} is valid.")
        window.write_event_value(
            "-ONLINE CHECK FOR EST-",
            [True, "text_valid_status", "OK", "green"],
        )
    elif f"The document {doc_num} is invalid." in page:
        print(f"[-] The document {doc_num} is invalid.")
        window.write_event_value(
            "-ONLINE CHECK FOR EST-",
            [False, "text_valid_status", "INVALID", "red"],
        )
    elif f"The document {doc_num} has not been issued." in page:
        print(f"[-] The document {doc_num} has not been issued.")
        window.write_event_value(
            "-ONLINE CHECK FOR EST-",
            [False, "text_valid_status", "NOT ISSUED", "red"],
        )
    elif f"The document {doc_num} is a specimen." in page:
        print(f"[-] The document {doc_num} is a specimen.")
        window.write_event_value(
            "-ONLINE CHECK FOR EST-",
            [False, "text_valid_status", "SPECIMEN", "red"],
        )
    else:
        print("[-] politsei.ee can't be reached!")
        window.write_event_value(
            "-ONLINE CHECK FOR EST-",
            [False, "text_valid_status", "ERROR", "red"],
        )


def download_certs(CSCA_certs_dir: Path, crls_dir: Path) -> None:
    """
    Download Estonian CSCA certificates and CRL
    """
    print("[+] Downloading CSCA certificates and CRLs.")
    csca_address = "https://pki.politsei.ee/"
    csca_certs_links = [
        "csca_Estonia_2007.cer",
        "csca_Estonia_2009.crt",
        "csca_Estonia_2012.cer",
        "csca_Estonia_2015.cer",
        "csca_Estonia_2016.cer",
        "csca_Estonia_2019.cer",
        "csca_Estonia_2020.der",
    ]

    # Get the crl
    subprocess.run(
        ["wget", "-N", "-P", os.path.abspath(crls_dir), csca_address + "csca.crl"],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        check=True,
    )
    # Get csca certificates
    for link in csca_certs_links:
        subprocess.run(
            ["wget", "-N", "-P", os.path.abspath(CSCA_certs_dir), csca_address + link],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            check=True,
        )
