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
# You should have received a copy of the GNU Lesser General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
IPFIX Transport Session state management (RFC 7011 §8, §10).

A :class:`Session` holds the stateful context shared across IPFIX messages
within a transport session: active templates (scoped by Observation Domain ID),
optional UDP template lifetimes (RFC 7011 §8.3), and per-domain sequence
numbers (RFC 7011 §3.1).

Separating :class:`Session` from :class:`ipfix.message.MessageBuffer` allows
UDP collectors and exporters to share template and sequence state cleanly
across individual datagrams without keeping a single mutable buffer per peer.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .template import Template

SequenceGapHook = Callable[["Session", int, int, int, int], None]


class Session:
    """
    Holds IPFIX session state: templates, template lifetimes, and sequence numbers.

    :param template_lifetime: Optional template expiration time in seconds
                              (recommended for UDP collectors per RFC 7011 §8.3,
                              e.g. ``1800.0``). ``None`` disables expiration
                              (appropriate for TCP/SCTP/file sessions).
    :param sequence_gap_hook: Optional callback ``(session, odid, streamid,
                              expected_seq, received_seq)`` invoked when a
                              collected message header sequence number does not
                              match the expected sequence number.
    """

    def __init__(
        self,
        *,
        template_lifetime: float | None = None,
        sequence_gap_hook: SequenceGapHook | None = None,
    ) -> None:
        self.templates: dict[tuple[int, int], Template] = {}
        self.template_times: dict[tuple[int, int], float] = {}
        self.sequences: dict[tuple[int, int], int] = {}
        self._seen_sequences: set[tuple[int, int]] = set()
        self.template_lifetime: float | None = template_lifetime
        self.sequence_gap_hook: SequenceGapHook | None = sequence_gap_hook

    def _is_expired(self, key: tuple[int, int], now: float) -> bool:
        if self.template_lifetime is None:
            return False
        ts = self.template_times.get(key)
        if ts is None:
            return False
        return (now - ts) > self.template_lifetime

    def purge_expired_templates(self, *, now: float | None = None) -> int:
        """Remove all expired templates and return the count removed."""
        if self.template_lifetime is None:
            return 0
        current = time.monotonic() if now is None else now
        expired = [k for k in list(self.templates) if self._is_expired(k, current)]
        for k in expired:
            del self.templates[k]
            self.template_times.pop(k, None)
        return len(expired)

    def add_template(
        self, odid: int, tmpl: Template, *, now: float | None = None
    ) -> None:
        """Register or refresh a template for an Observation Domain ID."""
        key = (odid, tmpl.tid)
        self.templates[key] = tmpl
        self.template_times[key] = time.monotonic() if now is None else now

    def get_template(
        self, odid: int, tid: int, *, now: float | None = None
    ) -> Template:
        """Retrieve an active template; raises KeyError if missing or expired."""
        key = (odid, tid)
        if key not in self.templates:
            raise KeyError(key)
        if self.template_lifetime is not None:
            current = time.monotonic() if now is None else now
            if self._is_expired(key, current):
                del self.templates[key]
                self.template_times.pop(key, None)
                raise KeyError(key)
        return self.templates[key]

    def delete_template(self, odid: int, tid: int) -> Template | None:
        """Remove a template if present and return it (or None)."""
        key = (odid, tid)
        self.template_times.pop(key, None)
        return self.templates.pop(key, None)

    def withdraw_all_templates(
        self, odid: int, setid: int | None = None
    ) -> list[int]:
        """Withdraw all templates (optionally filtered by native setid) for odid."""
        removed: list[int] = []
        for k in list(self.templates):
            if k[0] == odid and (setid is None or self.templates[k].native_setid() == setid):
                del self.templates[k]
                self.template_times.pop(k, None)
                removed.append(k[1])
        return removed

    def active_template_ids(
        self, odid: int, *, now: float | None = None
    ) -> Iterator[int]:
        """Yield active (non-expired) template IDs for the given domain."""
        if self.template_lifetime is not None:
            self.purge_expired_templates(now=now)
        for domain, tid in list(self.templates):
            if domain == odid:
                yield tid

    def current_sequence(self, odid: int, streamid: int = 0) -> int:
        """Return the current sequence number for (odid, streamid)."""
        return self.sequences.setdefault((odid, streamid), 0)

    def increment_sequence(
        self, odid: int, streamid: int = 0, count: int = 1
    ) -> int:
        """Increment and return the sequence number mod 2^32."""
        key = (odid, streamid)
        val = (self.sequences.get(key, 0) + count) & 0xFFFFFFFF
        self.sequences[key] = val
        return val

    def check_sequence(
        self, odid: int, streamid: int, received_seq: int
    ) -> bool:
        """
        Verify a received IPFIX message header sequence number (RFC 7011 §3.1).

        On the first message for ``(odid, streamid)``, synchronizes to
        ``received_seq`` and returns ``True``. On subsequent messages, if
        ``received_seq`` differs from the expected sequence number, invokes
        ``sequence_gap_hook`` (if set), resynchronizes to ``received_seq``,
        and returns ``False``.
        """
        key = (odid, streamid)
        if key not in self._seen_sequences:
            self._seen_sequences.add(key)
            self.sequences[key] = received_seq & 0xFFFFFFFF
            return True

        expected = self.sequences.get(key, 0)
        if received_seq != expected:
            if self.sequence_gap_hook is not None:
                self.sequence_gap_hook(self, odid, streamid, expected, received_seq)
            self.sequences[key] = received_seq & 0xFFFFFFFF
            return False
        return True

    def reset(self) -> None:
        """Clear all templates and sequence state."""
        self.templates.clear()
        self.template_times.clear()
        self.sequences.clear()
        self._seen_sequences.clear()
