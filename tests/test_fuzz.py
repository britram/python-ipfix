import io

from hypothesis import given, settings
from hypothesis import strategies as st

import ipfix.ie as ie
import ipfix.message as message
import ipfix.testutils as testutils
import ipfix.v9pdu as v9pdu
from ipfix.template import IpfixDecodeError


def _init_once():
    if not ie._ieForNum:
        ie.use_iana_default()


@settings(max_examples=200, deadline=None)
@given(data=st.binary(max_size=1024))
def test_fuzz_ipfix_arbitrary_bytes(data):
    """Arbitrary bytes must never hang or raise unhandled exceptions."""
    _init_once()
    before_ie_count = len(ie._ieForNum)
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(data)
        list(msg.namedict_iterator())
    except (IpfixDecodeError, EOFError):
        pass
    assert len(ie._ieForNum) == before_ie_count


@settings(max_examples=200, deadline=None)
@given(
    idx=st.integers(min_value=0, max_value=len(testutils._stored_test_message) - 1),
    val=st.integers(min_value=0, max_value=255),
    truncate=st.integers(min_value=0, max_value=len(testutils._stored_test_message)),
)
def test_fuzz_ipfix_mutated_valid_message(idx, val, truncate):
    """Single-byte mutations and truncations of a valid IPFIX message stay safe."""
    _init_once()
    mutated = bytearray(testutils._stored_test_message)
    mutated[idx] = val
    buf = bytes(mutated[:truncate])
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(buf)
        list(msg.namedict_iterator())
    except (IpfixDecodeError, EOFError):
        pass


@settings(max_examples=200, deadline=None)
@given(data=st.binary(max_size=512))
def test_fuzz_v9pdu_arbitrary_bytes(data):
    """Arbitrary bytes fed to NetFlow v9 decoders must never hang or crash."""
    _init_once()
    try:
        list(v9pdu.SinglePduBuffer(data).namedict_iterator())
    except (IpfixDecodeError, EOFError):
        pass

    try:
        list(v9pdu.from_stream(io.BytesIO(data)).namedict_iterator())
    except (IpfixDecodeError, EOFError):
        pass
