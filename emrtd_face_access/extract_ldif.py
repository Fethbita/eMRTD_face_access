#!/usr/bin/env python3
# Copyright (c) 2019 Andy Qua
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Extract unique CSCA certificates from ICAO PKD Master Lists"""

from subprocess import Popen, PIPE
from typing import Union, Tuple, List, BinaryIO

from ldif import LDIFRecordList
from OpenSSL.crypto import (
    load_certificate,
    load_crl,
    FILETYPE_ASN1,
    X509,
    X509Store,
)

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_node_first_child,
    asn1_node_next,
)
from emrtd_face_access.certs import is_self_signed, print_valid_time


def execute(cmd: str, data: Union[bytes, None] = None) -> Tuple[bytes, bytes]:
    """
    Run a command and capture the output
    """
    with Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:
        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None
        if data is not None:
            proc.stdin.write(data)
            proc.stdin.close()
        out = proc.stdout.read()
        err = proc.stderr.read()

    return (out, err)


def unique_hash(cert: X509) -> bool:
    """
    Save unique fingerprints of the CSCA certificates seen.
    """
    if "fingerprints" not in unique_hash.__dict__:
        unique_hash.fingerprints = []

    fingerprint = cert.digest("sha256")
    if fingerprint not in unique_hash.fingerprints:
        unique_hash.fingerprints.append(fingerprint)
        return True

    return False


def extract_certificates(signed_data: bytes) -> List[X509]:
    """
    Return CSCA certificates from Master List
    """
    certs = []

    i = asn1_node_root(signed_data)
    last_byte = i[2]
    i = asn1_node_first_child(signed_data, i)
    i = asn1_node_next(signed_data, i)
    i = asn1_node_first_child(signed_data, i)
    while True:
        data = asn1_get_all(signed_data, i)
        certs.append(load_certificate(FILETYPE_ASN1, data))
        if i[2] == last_byte:
            break
        i = asn1_node_next(signed_data, i)

    print(f"\t[+] Extracted {len(certs)} certs")
    return certs


def parse_csca_certs(master_list: BinaryIO, store: X509Store) -> None:
    """
    Parse CSCA certificates from the ICAO PKD ML ldif
    """
    parser = LDIFRecordList(master_list)
    parser.parse_entry_records()

    unique_certs: List[X509] = []

    for record in parser.all_records:
        if "CscaMasterListData" not in record[1]:
            continue
        print(f"\t[i] Reading {record[1]['cn'][0]}")
        cmd = "openssl cms -inform der -noverify -verify"
        (signed_data, err) = execute(cmd, record[1]["CscaMasterListData"][0])

        if err.decode("utf8").strip() != "Verification successful":
            # print(f"\t[-] [{err.decode('utf8')}]")
            print("\t[-] Verification of Masterlist data failed\n")
            continue
        print("\t[+] MasterList Verification successful")

        cert_list = extract_certificates(signed_data)

        print("\t[i] Removing duplicates")
        unique_certs_from_ml = [x for x in cert_list if unique_hash(x)]

        print(f"\t[i] Removed {len(cert_list)-len(unique_certs_from_ml)} duplicate certificates\n")
        unique_certs = unique_certs + unique_certs_from_ml

    print(f"\t[i] Total unique entries: {len(unique_certs)}\n")

    for cert in unique_certs:
        if is_self_signed(cert):
            print(f"\t[+] Loaded certificate: {cert.get_subject().countryName}")
            print_valid_time("\t\t", cert)
            store.add_cert(cert)


def parse_crls(crls: BinaryIO, store: X509Store) -> None:
    """
    Parse CRLs from the ICAO PKD DSC-CRL ldif
    """
    parser = LDIFRecordList(crls)
    parser.parse_entry_records()
    for record in parser.all_records:
        if "certificateRevocationList;binary" in record[1]:
            CRL = load_crl(FILETYPE_ASN1, record[1]["certificateRevocationList;binary"][0])
            print(f"\t[+] Loaded CRL: {record[1]['cn'][0]}")
            store.add_crl(CRL)
