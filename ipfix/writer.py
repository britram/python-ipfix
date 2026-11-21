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
Interfaces to write IPFIX Messages to streams (TCP/files) and datagrams (UDP).
"""

from __future__ import annotations

import time
from typing import Any

from . import message, template
from .session import Session


class MessageStreamWriter:
    """
    Writes records to a stream of IPFIX messages.

    Uses an :class:`ipfix.message.MessageBuffer` internally, and continually
    writes records into messages, exporting messages to the stream each time the
    maximum message size (MTU) is reached. Use :func:`to_stream` to get an
    instance.

    Suitable for writing to IPFIX files (see :rfc:`5655`) as well as to TCP
    sockets. When writing a stream to a file, use mode='wb'.
    """

    def __init__(
        self, stream: Any, mtu: int = 65535, *, session: Session | None = None
    ) -> None:
        self.stream = stream
        self.session = session if session is not None else Session()
        self.msg = message.MessageBuffer(session=self.session)
        self.msg.mtu = mtu
        self.msgcount = 0
        self.curtid: int | None = None

    def _retry_after_flush(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except message.EndOfMessage:
            self.flush()
            return fn(*args, **kwargs)

    def set_domain(self, odid: int) -> None:
        """
        Sets the observation domain for subsequent messages sent with
        this Writer.
        """
        if self.msg.export_needs_flush():
            self.msg.write_message(self.stream)
            self.msgcount += 1
        self.msg.begin_export(odid)

    def add_template(self, tmpl: template.Template) -> None:
        """
        Add a template to this Writer. Adding a template makes it
        available for use for exporting records; see :meth:`set_export_template`.
        """
        self._retry_after_flush(message.MessageBuffer.add_template, self.msg, tmpl)

    def set_export_template(self, tid: int) -> None:
        """
        Set the template to be used for export by subsequent calls to
        :meth:`export_namedict` and :meth:`export_tuple`.
        """
        self.curtid = tid
        self._retry_after_flush(
            message.MessageBuffer.export_ensure_set, self.msg, self.curtid
        )

    def export_namedict(self, rec: dict[str, Any]) -> None:
        """Export a record to the message, using the current template."""
        self._retry_after_flush(
            message.MessageBuffer.export_ensure_set, self.msg, self.curtid
        )
        self._retry_after_flush(
            message.MessageBuffer.export_namedict, self.msg, rec
        )

    def export_tuple(self, rec: tuple[Any, ...]) -> None:
        self._retry_after_flush(
            message.MessageBuffer.export_ensure_set, self.msg, self.curtid
        )
        self._retry_after_flush(
            message.MessageBuffer.export_tuple, self.msg, rec
        )

    def flush(self) -> None:
        """Export an in-progress Message immediately."""
        if not self.msg.export_needs_flush():
            return
        setid = self.msg.cursetid
        self.msg.write_message(self.stream)
        self.msgcount += 1
        self.msg.begin_export()
        if setid is not None:
            self.msg.export_ensure_set(setid)


class DatagramWriter:
    """
    Writes IPFIX messages as MTU-bounded UDP datagrams with automatic
    periodic template refresh (RFC 7011 §10.3.6).

    :param send_fn: Callable accepting a ``bytes`` datagram (e.g.,
                    ``sock.send`` on a connected UDP socket, or
                    ``lambda b: sock.sendto(b, addr)``).
    :param mtu: Maximum IPFIX message size in bytes (default ``1400`` to avoid
                IP fragmentation over standard Ethernet MTUs).
    :param template_refresh_interval: Seconds between automatic re-export of
                                      active templates (default ``600.0``;
                                      ``None`` disables periodic refresh).
    :param session: Optional :class:`ipfix.session.Session`.
    """

    def __init__(
        self,
        send_fn: Any,
        mtu: int = 1400,
        *,
        template_refresh_interval: float | None = 600.0,
        session: Session | None = None,
    ) -> None:
        self.send_fn = send_fn
        self.session = session if session is not None else Session()
        self.msg = message.MessageBuffer(session=self.session)
        self.msg.mtu = mtu
        self.template_refresh_interval = template_refresh_interval
        self._last_template_refresh: float | None = None
        self.msgcount = 0
        self.curtid: int | None = None

    def _maybe_refresh_templates(self, *, now: float | None = None) -> None:
        if self.template_refresh_interval is None:
            return
        current = time.monotonic() if now is None else now
        if self._last_template_refresh is None:
            self._last_template_refresh = current
            return
        if (current - self._last_template_refresh) >= self.template_refresh_interval:
            self.refresh_templates(now=current)

    def refresh_templates(self, *, now: float | None = None) -> None:
        """Re-export all active templates in the current domain."""
        for tid in list(self.msg.active_template_ids()):
            try:
                self.msg.export_template(tid)
            except message.EndOfMessage:
                self.flush()
                self.msg.export_template(tid)
        self._last_template_refresh = time.monotonic() if now is None else now

    def _retry_after_flush(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except message.EndOfMessage:
            self.flush()
            return fn(*args, **kwargs)

    def set_domain(self, odid: int) -> None:
        if self.msg.export_needs_flush():
            self.flush()
        self.msg.begin_export(odid)

    def add_template(self, tmpl: template.Template) -> None:
        self._retry_after_flush(message.MessageBuffer.add_template, self.msg, tmpl)
        self._last_template_refresh = time.monotonic()

    def set_export_template(self, tid: int) -> None:
        self.curtid = tid
        self._retry_after_flush(
            message.MessageBuffer.export_ensure_set, self.msg, self.curtid
        )

    def export_namedict(self, rec: dict[str, Any]) -> None:
        self._maybe_refresh_templates()
        self._retry_after_flush(
            message.MessageBuffer.export_ensure_set, self.msg, self.curtid
        )
        self._retry_after_flush(
            message.MessageBuffer.export_namedict, self.msg, rec
        )

    def export_tuple(self, rec: tuple[Any, ...]) -> None:
        self._maybe_refresh_templates()
        self._retry_after_flush(
            message.MessageBuffer.export_ensure_set, self.msg, self.curtid
        )
        self._retry_after_flush(
            message.MessageBuffer.export_tuple, self.msg, rec
        )

    def flush(self) -> None:
        """Send the in-progress IPFIX message as a single UDP datagram."""
        if not self.msg.export_needs_flush():
            return
        setid = self.msg.cursetid
        self.send_fn(self.msg.to_bytes())
        self.msgcount += 1
        self.msg.begin_export()
        if setid is not None:
            self.msg.export_ensure_set(setid)


def to_stream(
    stream: Any, mtu: int = 65535, *, session: Session | None = None
) -> MessageStreamWriter:
    """
    Get a MessageStreamWriter for a given stream.

    :param stream: stream to write
    :param mtu: maximum message size in bytes; defaults to 65535,
                the largest possible IPFIX message.
    :param session: optional :class:`ipfix.session.Session`
    :return: a :class:`MessageStreamWriter` wrapped around the stream.
    """
    return MessageStreamWriter(stream, mtu, session=session)
