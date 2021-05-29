#!/usr/bin/env python3
# Copyright (c) 2021 Burak Can
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Functions related to card communication; APDU send etc."""

from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.CardConnectionDecorator import CardConnectionDecorator
from smartcard.Exceptions import CardConnectionException
from smartcard.CardMonitoring import CardObserver
from smartcard.Exceptions import NoCardException
from smartcard.util import toHexString

from emrtd_face_access.apdu import APDU
from emrtd_face_access.secure_messaging import secure_messaging, process_rapdu, ReplyAPDUError
from emrtd_face_access.secure_messaging_object import SMObject
from emrtd_face_access.byte_operations import nb
from emrtd_face_access.print_to_sg import SetInterval

print = SetInterval().print


class CardWatcher(CardObserver):
    def __init__(self, q, q2) -> None:
        super().__init__()
        self.queue = q
        self.queue2 = q2
        # fmt: off
        self.validcards = [
            [0x3B, 0xDB, 0x96, 0x00, 0x80, 0xB1, 0xFE, 0x45, 0x1F, 0x83, 0x00, 0x12, 0x23, 0x3F, 0x53, 0x65, 0x49, 0x44, 0x0F, 0x90, 0x00, 0xF1],
        ]
        self.knowncards = [
            # jTOP SLE66-powered ID cards (EstEID 3.0 contactless)
            [0x3B, 0x89, 0x80, 0x01, 0x4D, 0x54, 0x43, 0x4F, 0x53, 0x70, 0x02, 0x01, 0x05, 0x38],
            # jTOP SLE66-powered ID cards (EstEID 3.0 "JavaCard" cold)
            [0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0xA8],
            # jTOP SLE66-powered ID cards (EstEID 3.0 (18.01.2011) warm)
            [0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF],
            # jTOP SLE78-powered ID cards (contactless)
            [0x3B, 0x88, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x77, 0x81, 0x91, 0x00, 0x6E],
            # jTOP SLE78-powered ID cards (cold)
            [0x3B, 0xFA, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0xFE, 0x65, 0x49, 0x44, 0x20, 0x2F, 0x20, 0x50, 0x4B, 0x49, 0x03], 
            # jTOP SLE78-powered ID cards (warm)
            [0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF],
        ]
        # fmt: on

    def update(self, _, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            print("[+] Card ATR: " + toHexString(card.atr))
            if card.atr in self.validcards:
                try:
                    card.connection = card.createConnection()
                    card.connection.connect()
                except (NoCardException, CardConnectionException) as e:
                    continue
                self.queue2.put(["Valid card", card.connection, card.atr])
            else:
                try:
                    card.connection = card.createConnection()
                    card.connection.connect()
                    # Select the Master File (MF)
                    _, sw1, sw2 = card.connection.transmit([0x00, 0xA4, 0x00, 0x0C])
                    if [sw1, sw2] != [0x90, 0x00]:
                        continue
                    # Select the catalogue EEEE
                    _, sw1, sw2 = card.connection.transmit([0x00, 0xA4, 0x01, 0x0C, 0x02, 0xEE, 0xEE])
                    if [sw1, sw2] != [0x90, 0x00]:
                        continue
                    # Select the file 5044
                    _, sw1, sw2 = card.connection.transmit([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x50, 0x44])
                    if [sw1, sw2] != [0x90, 0x00]:
                        continue
                    # Read issue date
                    issue_date, sw1, sw2 = card.connection.transmit([0x00, 0xB2, 0x0B, 0x04])
                    if [sw1, sw2] != [0x90, 0x00]:
                        continue
                    issue = bytes(issue_date).decode("cp1252")
                    # Read type of residence permit
                    doc_type, sw1, sw2 = card.connection.transmit([0x00, 0xB2, 0x0C, 0x04])
                    if [sw1, sw2] != [0x90, 0x00]:
                        continue
                    doc_type_text = bytes(doc_type).decode("cp1252")
                    if doc_type_text.isspace():
                        doc_type_text = "ID card"
                    else:
                        doc_type_text = "residence permit"
                    self.queue2.put(["Known card", doc_type_text, issue])
                except (NoCardException, CardConnectionException) as e:
                    continue
        for card in removedcards:
            print("[-] Removed card ATR: " + toHexString(card.atr))
            self.queue.put("Disconnect")
            self.queue2.put("Disconnect")


def wait_for_card() -> CardConnectionDecorator:
    """
    Wait for card connection and return channel to the card.
    """
    channel = CardRequest(timeout=None).waitforcard().connection
    # uncomment for traching APDUs
    # observer = DisconnectWatcher()
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
