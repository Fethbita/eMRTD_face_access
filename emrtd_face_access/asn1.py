#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""This module has ASN1 related functions"""

from subprocess import Popen, PIPE, STDOUT
from typing import List


def len2int(first_n_bytes: bytes) -> int:
    """
    Gets the asn1length and returns it as integer as explained in 9303-10 p14.
    """
    if not first_n_bytes[1] >> 7:
        data_len = first_n_bytes[1] + 2
    else:
        length_of_length = (1 << 7) ^ first_n_bytes[1]
        data_len = (
            int.from_bytes(first_n_bytes[2 : length_of_length + 2], byteorder="big")
            + length_of_length
            + 2
        )
    return data_len


# https://stackoverflow.com/a/53915038/
def encode_variable_length_quantity(v: int) -> List[int]:
    """
    Break it up in groups of 7 bits starting from the lowest significant bit
    For all the other groups of 7 bits than lowest one, set the MSB to 1
    """
    m = 0x00
    output: List[int] = []
    while v >= 0x80:
        output.insert(0, (v & 0x7F) | m)
        v = v >> 7
        m = 0x80
    output.insert(0, v | m)
    return output


def encode_oid_string(oid_str: str) -> bytes:
    """oid string value to bytes"""
    a = [int(x) for x in oid_str.split(".")]
    oid = [a[0] * 40 + a[1]]  # First two items are coded by a1*40+a2
    # The rest is Variable-length_quantity
    for n in a[2:]:
        oid.extend(encode_variable_length_quantity(n))
    oid.insert(0, len(oid))  # Add a Length
    oid.insert(0, 0x06)  # Add a Type (0x06 for Object Identifier)
    return bytes(oid)


def dump_asn1(der: bytes) -> str:
    """Use dumpasn1 program and return the output"""
    p = Popen(["dumpasn1", "-a", "-"], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    dump = p.communicate(input=der)[0]
    return dump.decode("utf8")


def get_digestalg_name(digest_alg_oid: bytes) -> str:
    """Returns digest algorithm name from oid"""
    digest_alg_oid_dict = {
        encode_oid_string("1.3.36.3.2.3"): "ripemd256",
        encode_oid_string("1.3.36.3.2.2"): "ripemd128",
        encode_oid_string("1.3.36.3.2.1"): "ripemd160",
        encode_oid_string("1.2.156.10197.1.401"): "sm3",
        encode_oid_string("2.16.840.1.101.3.4.2.6"): "sha512_256",
        encode_oid_string("2.16.840.1.101.3.4.2.5"): "sha512_224",
        encode_oid_string("2.16.840.1.101.3.4.2.4"): "sha224",
        encode_oid_string("2.16.840.1.101.3.4.2.3"): "sha512",
        encode_oid_string("2.16.840.1.101.3.4.2.2"): "sha384",
        encode_oid_string("2.16.840.1.101.3.4.2.1"): "sha256",
        encode_oid_string("1.2.643.2.2.9"): "gost3411",
        encode_oid_string("1.3.14.3.2.26"): "sha1",
        encode_oid_string("1.2.840.113549.2.5"): "md5",
        encode_oid_string("1.2.840.113549.2.4"): "md4",
        encode_oid_string("1.2.840.113549.2.2"): "md2",
    }
    if digest_alg_oid in digest_alg_oid_dict:
        return digest_alg_oid_dict[digest_alg_oid]
    raise ValueError("[-] Hash algorithm is not recognized.")


def asn1_len(value_bytes: bytes) -> bytes:
    """
    helper function - should be used in other functions to calculate length octet(s)\n
    value_bytes - bytes containing TLV value byte(s)\n
    returns length (L) byte(s) for TLV
    """
    length = len(value_bytes)
    if length < 128:
        return bytes([length])

    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, byteorder="big")

    length_of_length_bytes = bytes([(1 << 7) | len(length_bytes)])
    return length_of_length_bytes + length_bytes


def asn1_integer(i: bytes) -> bytes:
    """
    i - arbitrary byte\n
    returns DER encoding of INTEGER\n
    Type = Universal, primitive, tag 2\n
    00 0 00010
    """
    type_byte = b"\x02"

    if i[0] >> 7:
        i = b"\x00" + i
    return type_byte + asn1_len(i) + i


def asn1_sequence(der: bytes) -> bytes:
    """
    der - DER bytes to encapsulate into sequence\n
    returns DER encoding of SEQUENCE\n
    Type = Universal, constructed, tag 16\n
    00 1 10000
    """
    type_byte = b"\x30"

    payload = der
    return type_byte + asn1_len(payload) + payload
