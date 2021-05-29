#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Module for extracting ldif files in ICAO PKD"""

import os
from pathlib import Path

from OpenSSL.crypto import (
    load_certificate,
    load_crl,
    FILETYPE_ASN1,
    FILETYPE_PEM,
    X509Store,
    X509StoreFlags,
)

from emrtd_face_access.certs import is_self_signed, print_valid_time
from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print


def build_store(CSCA_certs_dir: Path, crls_dir: Path, ml_dir: Path, dsccrl_dir: Path) -> X509Store:
    """
    Add CSCA certificates and CRLs into the store
    """
    if "store" in build_store.__dict__:
        return build_store.store
    else:
        store = X509Store()

    # Add CA certificates to the store
    # https://www2.politsei.ee/en/nouanded/isikut-toendavad-dokumendid/cert.dot
    print("[↳] Loading up CSCA certificates")

    # Load individual CSCA certificates
    for file in os.listdir(CSCA_certs_dir):
        with open(os.path.join(CSCA_certs_dir, file), "rb") as infile:
            cert = infile.read()
            if not cert.startswith(b"-----BEGIN CERTIFICATE-----"):
                try:
                    CSCA = load_certificate(FILETYPE_ASN1, cert)
                except:
                    print(
                        f"\t[-] Error while reading {os.path.join(CSCA_certs_dir, file)}, skipping..."
                    )
                    continue
                if is_self_signed(CSCA):
                    store.add_cert(CSCA)
                    print(f"\t[+] Loaded certificate: {CSCA.get_subject().countryName}")
                    print_valid_time("\t\t", CSCA)
                continue
            for onecert in cert.split(b"-----END CERTIFICATE-----"):
                onecert = onecert.strip()
                if not onecert.startswith(b"-----BEGIN CERTIFICATE-----"):
                    continue
                try:
                    CSCA = load_certificate(FILETYPE_PEM, onecert + b"\n-----END CERTIFICATE-----")
                except:
                    print(
                        f"\t[-] Error while reading {os.path.join(CSCA_certs_dir, file)}, skipping..."
                    )
                    continue
                if is_self_signed(CSCA):
                    store.add_cert(CSCA)
                    print(f"\t[+] Loaded certificate: {CSCA.get_subject().countryName}")
                    print_valid_time("\t\t", CSCA)

    print("[↳] Loading up CRLs")
    # Load individual CRLs
    for file in os.listdir(crls_dir):
        with open(os.path.join(crls_dir, file), "rb") as infile:
            try:
                CRL = load_crl(FILETYPE_ASN1, infile.read())
            except:
                print(f"\t[-] Error while reading {os.path.join(crls_dir, file)}, skipping...")
                continue
            store.add_crl(CRL)
            print(f"\t[+] Loaded CRL: {file}")

    # store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.CRL_CHECK_ALL)
    # some countries don't have CRL in ICAO PKD
    store.set_flags(X509StoreFlags.CRL_CHECK_ALL)

    build_store.store = store

    return build_store.store
