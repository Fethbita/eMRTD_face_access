#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""X509 certificate related functions"""

from datetime import datetime
from typing import Dict, Union

from OpenSSL.crypto import (
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
    Error,
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


def get_extension_data(cert: X509) -> Dict[bytes, Union[str, bytes]]:
    """
    Returns the extension data of an X509 certificate.
    """
    extensions = [cert.get_extension(i) for i in range(cert.get_extension_count())]
    extension_data = {}
    for e in extensions:
        short_name = e.get_short_name()
        try:
            if short_name == b"authorityKeyIdentifier":
                prefix = "keyid:"
                extension_data[short_name] = e.__str__()[
                    e.__str__().startswith(prefix) and len(prefix) :
                ].strip()
            elif short_name in [
                b"subjectKeyIdentifier",
                b"extendedKeyUsage",
                b"basicConstraints",
                b"crlDistributionPoints",
            ]:
                extension_data[short_name] = e.__str__()
            else:
                extension_data[short_name] = e.get_data()
        except Error:
            extension_data[short_name] = e.get_data()

    return extension_data


def print_valid_time(prefix: str, cert: X509) -> None:
    """Print validity time of the certificate"""
    validfrom_time = cert.get_notBefore()
    validfrom_datetime = datetime.strptime(validfrom_time.decode("utf-8"), "%Y%m%d%H%M%SZ")
    validto_time = cert.get_notAfter()
    validto_datetime = datetime.strptime(validto_time.decode("utf-8"), "%Y%m%d%H%M%SZ")
    print(f"{prefix}valid from: {validfrom_datetime}")
    print(f"{prefix}valid to  : {validto_datetime}")
