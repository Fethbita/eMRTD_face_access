#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Module for passive authentication related functions"""

from typing import Tuple, List, Optional
import hashlib
import hmac

from OpenSSL.crypto import (
    verify,
    load_certificate,
    FILETYPE_ASN1,
    X509StoreContext,
    X509StoreContextError,
)

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_get_value,
    asn1_get_value_of_type,
    asn1_node_next,
    asn1_node_first_child,
)

from emrtd_face_access.asn1 import dump_asn1, encode_oid_string, get_digestalg_name
from emrtd_face_access.icao_pkd_load import build_store


class PassiveAuthenticationError(Exception):
    """Exception to raise when a Passive Authentication Error occurs."""


class PassiveAuthenticationCriticalError(Exception):
    """Exception to raise when a Critical Passive Authentication Error occurs."""


def passive_auth(
    efsod: bytes, ee_deviant_doc: bool = False, dump: bool = False
) -> Tuple[str, bytes, bytes, Optional[List[PassiveAuthenticationError]]]:
    """
    Do Passive Authentication

    :returns:
    hash_alg that is used to hash DGs,
    data_group_hash_values
    """
    exceptions: List[PassiveAuthenticationError] = []

    # get root node
    i = asn1_node_root(efsod)
    # unpack application data 0x77
    i = asn1_node_first_child(efsod, i)
    # unpack sequence
    i = asn1_node_first_child(efsod, i)
    # print id-signedData OBJECT IDENTIFIER
    if dump:
        print(dump_asn1(asn1_get_all(efsod, i)))
    # get 2nd item inside (SignedData EXPLICIT tagged)
    i = asn1_node_next(efsod, i)
    # unpack SignedData EXPLICIT tag
    i = asn1_node_first_child(efsod, i)
    # get 1st item inside (CMSVersion Value = v3)
    i = asn1_node_first_child(efsod, i)
    # get 2nd item (DigestAlgorithmIdentifiers) collection of message digest algorithm identifiers.
    # There MAY be any number of elements in the collection, including zero.
    i = asn1_node_next(efsod, i)
    # get 3rd item (EncapsulatedContentInfo) (LDS Document Security Object)
    i = asn1_node_next(efsod, i)

    # get 1st item inside (eContentType)
    # (OID joint-iso-itu-t (2) international(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1))
    j = asn1_node_first_child(efsod, i)
    e_content_type = asn1_get_all(efsod, j)
    # get the EXPLICIT tagged encoded contents of ldsSecurityObject
    j = asn1_node_next(efsod, j)
    # get the encoded contents of ldsSecurityObject
    j = asn1_node_first_child(efsod, j)
    # print the value of eContent hash
    encapsulated_content = asn1_get_value_of_type(efsod, j, "OCTET STRING")
    del j

    signer_infos, certificates, crls = None, None, None
    while signer_infos is None:
        # https://stackoverflow.com/a/52041365/6077951
        # get 4th item
        i = asn1_node_next(efsod, i)
        if efsod[i[0]] == 0xA0:
            # Constructed, Context-Specific 0
            certificates = i
            print("[+] CertificateSet exist")
        elif efsod[i[0]] == 0xA1:
            # Constructed, Context-Specific 1
            crls = i
            print("[+] Crls exist")
        else:
            signer_infos = i

    # The inspection system SHALL build and validate a certification path
    # from a Trust Anchor to the Document Signer Certificate used to
    # sign the Document Security Object (SOD) according to Doc 9303-11.

    # store was already built in the first run
    store = build_store.store

    doc_sig_cert = asn1_get_value(efsod, certificates)

    if certificates is not None:
        if ee_deviant_doc:
            doc_sig_cert = add_seconds_to_certificate(doc_sig_cert, 43200)
        CDS = load_certificate(FILETYPE_ASN1, doc_sig_cert)
        store_ctx = X509StoreContext(store, CDS)
        try:
            if store_ctx.verify_certificate() is None:
                print("[+] Document Signer Certificate is signed by a CSCA certificate")
        except X509StoreContextError as ex:
            exceptions.append(
                PassiveAuthenticationError(
                    "[-] Document Signer Certificate is not signed "
                    "by a CSCA certificate or is invalid!\n" + str(ex)
                )
            )
    else:
        raise PassiveAuthenticationCriticalError(
            "[-] This application doesn't support this kind of document yet!"
        )

    # get 1st signerInfo inside signerInfos
    i = asn1_node_first_child(efsod, signer_infos)
    # get 1st item inside 1st signerInfo (CMSVersion)
    i = asn1_node_first_child(efsod, i)
    signer_info_ver = int.from_bytes(asn1_get_value_of_type(efsod, i, "INTEGER"), byteorder="big")

    issuer_and_serial_number, subject_key_identifier = None, None
    # get 2nd item inside 1st signerInfo (SignerIdentifier)
    i = asn1_node_next(efsod, i)
    if signer_info_ver == 1:
        issuer_and_serial_number = i
    elif signer_info_ver == 3:
        subject_key_identifier = i

    if dump:
        print(dump_asn1(asn1_get_all(efsod, issuer_and_serial_number or subject_key_identifier)))

    # get 3rd item inside 1st signerInfo (DigestAlgorithmIdentifier)
    i = asn1_node_next(efsod, i)
    # get hash algorithm used for encapsulatedContent and SignedAttrs
    hash_alg = asn1_get_all(efsod, asn1_node_first_child(efsod, i))
    try:
        hash_alg = get_digestalg_name(hash_alg)
    except ValueError as ex:
        raise PassiveAuthenticationCriticalError("[-] Hash algorithm is not recognized.") from ex

    # get 4th item inside 1st signerInfo ([0] IMPLICIT SignedAttributes)
    i = asn1_node_next(efsod, i)
    # use EXPLICIT SET OF tag, rather than of the IMPLICIT [0] tag
    signed_attrs = asn1_get_all(efsod, i)
    signed_attrs = b"\x31" + signed_attrs[1:]

    # get the first Attribute from SignedAttributes
    j = asn1_node_first_child(efsod, i)
    content_type, signed_attrs_hash = None, None
    while content_type is None or signed_attrs_hash is None:
        # get the content-type and the message-digest
        k = asn1_node_first_child(efsod, j)
        # contentType
        if asn1_get_all(efsod, k) == encode_oid_string("1.2.840.113549.1.9.3"):
            # then the content-type attribute value MUST match
            # the SignedData encapContentInfo eContentType value.
            # checked in line 195
            k = asn1_node_next(efsod, k)
            k = asn1_node_first_child(efsod, k)
            content_type = asn1_get_all(efsod, k)
        # messageDigest
        elif asn1_get_all(efsod, k) == encode_oid_string("1.2.840.113549.1.9.4"):
            k = asn1_node_next(efsod, k)
            k = asn1_node_first_child(efsod, k)
            signed_attrs_hash = asn1_get_value_of_type(efsod, k, "OCTET STRING")
        j = asn1_node_next(efsod, j)
    del k, j

    hash_object = hashlib.new(hash_alg)
    hash_object.update(encapsulated_content)
    e_content_hash = hash_object.digest()
    del hash_object
    # print("[+] Calculated hash of eContent =", eContent_hash.hex())
    # print("[+] Hash of eContent in SignedAttributes =", signedAttrs_hash.hex())

    if e_content_type == content_type:
        print("[+] Content Type of eContent match with the Content Type in SignedAttributes")
    else:
        exceptions.append(
            PassiveAuthenticationError(
                "[-] Content Type of eContent DOES NOT "
                "match with the Content Type in SignedAttributes."
            )
        )

    if hmac.compare_digest(signed_attrs_hash, e_content_hash):
        print("[+] Hash of eContent match with the hash in SignedAttributes")
    else:
        exceptions.append(
            PassiveAuthenticationError(
                "[+] Hash of eContent DOES NOT match with the hash in SignedAttributes."
            )
        )

    # get 4th item inside 1st signerInfo (SignatureAlgorithmIdentifier)
    i = asn1_node_next(efsod, i)
    # get 5th item inside 1st signerInfo (SignatureValue)
    i = asn1_node_next(efsod, i)
    signature = asn1_get_value_of_type(efsod, i, "OCTET STRING")

    # Verify the signature with DS_cert using hash_alg
    try:
        if verify(CDS, signature, signed_attrs, hash_alg) is None:
            print("[+] The signature on EF_SOD is valid.")
    except ex:
        exceptions.append(
            PassiveAuthenticationError("[-] The signature on EF_SOD is not valid or failed.")
        )

    i = asn1_node_root(encapsulated_content)
    i = asn1_node_first_child(encapsulated_content, i)
    i = asn1_node_next(encapsulated_content, i)
    i = asn1_node_next(encapsulated_content, i)

    data_group_hash_values = asn1_get_all(encapsulated_content, i)

    if len(exceptions) == 0:
        return hash_alg, data_group_hash_values, doc_sig_cert, None
    return hash_alg, data_group_hash_values, doc_sig_cert, exceptions


def add_seconds_to_certificate(cert: bytes, seconds: int) -> bytes:
    from datetime import datetime, timedelta

    i = asn1_node_root(cert)  # Certificate
    i = asn1_node_first_child(cert, i)  # tbsCertificate
    i = asn1_node_first_child(cert, i)  # version
    i = asn1_node_next(cert, i)  # serialNumber
    i = asn1_node_next(cert, i)  # signature
    i = asn1_node_next(cert, i)  # issuer
    i = asn1_node_next(cert, i)  # validity
    i = asn1_node_first_child(cert, i)  # notBefore
    not_before = asn1_get_value(cert, i)
    if len(not_before) == 13:
        date_format = "%y%m%d%H%M%SZ"
    else:
        date_format = "%Y%m%d%H%M%SZ"
    date_time_obj = datetime.strptime(not_before.decode("utf-8"), date_format)
    cert = (
        cert[: i[1]]
        + (date_time_obj + timedelta(seconds=seconds)).strftime(date_format).encode("utf_8")
        + cert[i[2] + 1 :]
    )

    i = asn1_node_next(cert, i)  # notAfter
    not_after = asn1_get_value(cert, i)
    if len(not_after) == 13:
        date_format = "%y%m%d%H%M%SZ"
    else:
        date_format = "%Y%m%d%H%M%SZ"
    date_time_obj = datetime.strptime(not_after.decode("utf-8"), date_format)
    cert = (
        cert[: i[1]]
        + (date_time_obj + timedelta(seconds=seconds)).strftime(date_format).encode("utf_8")
        + cert[i[2] + 1 :]
    )

    return cert
