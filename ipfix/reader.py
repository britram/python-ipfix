#
# python-ipfix (c) 2013-2026 Brian Trammell.
#
# Many thanks to the mPlane consortium (http://www.ict-mplane.eu) for
# its material support of this effort.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Interfaces to read IPFIX Messages from streams (TCP/files) and datagrams (UDP).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from . import ie, message
from .session import Session


class MessageStreamReader:
    """
    Reads records from a stream of IPFIX messages.

    Uses an :class:`ipfix.message.MessageBuffer` internally, and continually reads
    messages from the given stream into the buffer, iterating over records,
    until the end of the stream. Use :func:`from_stream` to get an instance.

    Suitable for reading from IPFIX files (see :rfc:`5655`) as well as from
    TCP sockets with :class:`socketserver.StreamRequestHandler`.
    When opening a stream from a file, use mode='rb'.
    """

    def __init__(self, stream: Any, *, session: Session | None = None) -> None:
        self.stream = stream
        self.session = session if session is not None else Session()
        self.msg = message.MessageBuffer(session=self.session)
        self.msgcount = 0

    def namedict_iterator(self) -> Iterator[dict[str, Any]]:
        """
        Iterate over all records in the stream, as dicts mapping IE names
        to values.

        :returns: a name dictionary iterator
        """
        try:
            while True:
                self.msg.read_message(self.stream)
                for rec in self.msg.namedict_iterator():
                    yield rec
                    self.msgcount += 1
        except EOFError:
            return

    def tuple_iterator(
        self, ielist: ie.InformationElementList
    ) -> Iterator[tuple[Any, ...]]:
        """
        Iterate over all records in the stream containing all the IEs in
        the given ielist. Records are returned as tuples in ielist order.

        :param ielist: an instance of :class:`ipfix.ie.InformationElementList`
                       listing IEs to return as a tuple
        :returns: a tuple iterator for tuples as in ielist order
        """
        try:
            while True:
                self.msg.read_message(self.stream)
                for rec in self.msg.tuple_iterator(ielist):
                    yield rec
                    self.msgcount += 1
        except EOFError:
            return


class DatagramReader:
    """
    Reads IPFIX messages from UDP datagrams while maintaining per-peer
    :class:`ipfix.session.Session` state (templates, template lifetimes,
    and sequence numbers).

    Suitable for UDP collectors (e.g., :class:`socketserver.UDPServer` or
    ``asyncio.DatagramProtocol``) where each datagram arrives independently
    and templates may be sent in separate packets from data sets.
    """

    def __init__(
        self,
        *,
        template_lifetime: float | None = 1800.0,
        session: Session | None = None,
    ) -> None:
        self.template_lifetime = template_lifetime
        self._shared_session = session
        self.sessions: dict[Any, Session] = {}
        self.msgcount = 0

    def session_for_peer(self, peer: Any = None) -> Session:
        """Return (creating if needed) the :class:`Session` for ``peer``."""
        if self._shared_session is not None:
            return self._shared_session
        sess = self.sessions.get(peer)
        if sess is None:
            sess = Session(template_lifetime=self.template_lifetime)
            self.sessions[peer] = sess
        return sess

    def read_datagram(self, data: bytes | bytearray | memoryview, peer: Any = None) -> message.MessageBuffer:
        """Parse a single IPFIX UDP datagram using the peer's :class:`Session`."""
        sess = self.session_for_peer(peer)
        msg = message.MessageBuffer(session=sess)
        msg.from_bytes(data)
        self.msgcount += 1
        return msg

    def namedict_iterator(
        self, data: bytes | bytearray | memoryview, peer: Any = None
    ) -> Iterator[dict[str, Any]]:
        """Decode a single datagram and yield records as dicts."""
        msg = self.read_datagram(data, peer=peer)
        yield from msg.namedict_iterator()

    def tuple_iterator(
        self,
        data: bytes | bytearray | memoryview,
        ielist: ie.InformationElementList,
        peer: Any = None,
    ) -> Iterator[tuple[Any, ...]]:
        """Decode a single datagram and yield records as tuples."""
        msg = self.read_datagram(data, peer=peer)
        yield from msg.tuple_iterator(ielist)


def from_stream(stream: Any, *, session: Session | None = None) -> MessageStreamReader:
    """
    Get a MessageStreamReader for a given stream.

    :param stream: stream to read
    :param session: optional :class:`ipfix.session.Session`
    :return: a :class:`MessageStreamReader` wrapped around the stream.
    """
    return MessageStreamReader(stream, session=session)
