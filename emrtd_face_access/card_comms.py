#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Functions related to card communication; APDU send etc."""

from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.CardConnectionDecorator import CardConnectionDecorator

# from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver

from emrtd_face_access.apdu import APDU
from emrtd_face_access.secure_messaging import secure_messaging, process_rapdu, ReplyAPDUError
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.byte_operations import nb
from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print


def wait_for_card() -> CardConnectionDecorator:
    """
    Wait for card connection and return channel to the card.
    """

    channel = CardRequest(timeout=None).waitforcard().connection
    # uncomment for traching APDUs
    # observer = ConsoleCardConnectionObserver()
    # channel.addObserver(observer)
    print("[+] Selected reader:", channel.getReader())
    try:
        channel.connect(CardConnection.T1_protocol)
    except:
        print("[!] Fallback to T=0")
        channel.connect(CardConnection.T0_protocol)
    return channel


class CardCommunicationError(Exception):
    """Exception to raise when an error occurs during card communication."""


def send(sm_object: SMObject, apdu: APDU) -> bytes:
    """
    Send APDU to the channel and return the data if there are no errors.
    """
    channel = sm_object.channel
    apdu_bytes = secure_messaging(sm_object, apdu)

    data, sw1, sw2 = channel.transmit(list(apdu_bytes))

    # success
    if [sw1, sw2] == [0x90, 0x00]:
        try:
            data = process_rapdu(sm_object, bytes(data))
        except ReplyAPDUError as ex:
            raise CardCommunicationError("[-] Reply APDU MAC doesn't match!") from ex
        else:
            return data
    # signals that there is more data to read
    if sw1 == 0x61:
        print("[=] TAKE A LOOK! More data to read:", sw2)
        return data + send(
            sm_object, APDU(b"\x00", b"\xC0", b"\x00", b"\x00", Le=nb(sw2))
        )  # GET RESPONSE of sw2 bytes
    if sw1 == 0x6C:
        print("[=] TAKE A LOOK! Resending with Le:", sw2)
        return send(
            sm_object, APDU(apdu.cla, apdu.ins, apdu.p1, apdu.p2, Le=nb(sw2))
        )  # resend APDU with Le = sw2
    # probably error condition
    # channel.disconnect()
    print("[-] Card communication error occured.")
    print(
        "Error: %02x %02x, sending APDU: %s"
        % (sw1, sw2, " ".join(["{:02x}".format(x) for x in apdu_bytes]).upper())
    )
    print(
        "Plain APDU: "
        + " ".join(
            [
                "{:02x}".format(x)
                for x in (
                    apdu.get_command_header()
                    + (apdu.Lc or b"")
                    + (apdu.cdata or b"")
                    + (apdu.Le or b"")
                )
            ]
        ).upper()
    )
    raise CardCommunicationError(
        "Error: %02x %02x, sending APDU: %s"
        % (sw1, sw2, " ".join(["{:02x}".format(x) for x in apdu_bytes]).upper())
    )
