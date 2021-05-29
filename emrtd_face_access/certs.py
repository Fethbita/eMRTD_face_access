#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""X509 certificate related functions"""

from datetime import datetime

from OpenSSL.crypto import (
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
)
from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print


def is_self_signed(cert: X509) -> bool:
    """
    Checks if a X509 certificate is self signed.
    """
    store = X509Store()
    store.add_cert(cert)
    validfrom_time = cert.get_notBefore()
    validfrom_datetime = datetime.strptime(validfrom_time.decode("utf-8"), "%Y%m%d%H%M%SZ")
    store.set_time(validfrom_datetime)
    store_ctx = X509StoreContext(store, cert)
    try:
        store_ctx.verify_certificate()
        return True
    except X509StoreContextError:
        return False


def print_valid_time(prefix: str, cert: X509) -> None:
    """Print validity time of the certificate"""
    validfrom_time = cert.get_notBefore()
    validfrom_datetime = datetime.strptime(validfrom_time.decode("utf-8"), "%Y%m%d%H%M%SZ")
    validto_time = cert.get_notAfter()
    validto_datetime = datetime.strptime(validto_time.decode("utf-8"), "%Y%m%d%H%M%SZ")
    print(f"{prefix}valid from: {validfrom_datetime}")
    print(f"{prefix}valid to  : {validto_datetime}")
