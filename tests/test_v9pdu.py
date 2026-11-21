import io
import struct
from datetime import UTC, datetime
from ipaddress import ip_address

import pytest

import ipfix.ie as ie
import ipfix.v9pdu as v9pdu
from ipfix.template import IpfixDecodeError


@pytest.fixture(autouse=True)
def setup_iana():
    ie.clear_infomodel()
    ie.use_iana_default()
    yield
    ie.clear_infomodel()


def _build_v9_pdu(
    sets,
    *,
    reccount=1,
    sysuptime_ms=60000,
    export_epoch=1700000000,
    sequence=1,
    odid=42,
):
    hdr = struct.pack(
        "!HHLLLL",
        v9pdu.NETFLOW9_VERSION,
        reccount,
        sysuptime_ms,
        export_epoch,
        sequence,
        odid,
    )
    return hdr + b"".join(sets)


def _v9_template_set(tid, fields, pad=0):
    body = struct.pack("!HH", tid, len(fields))
    for num, length in fields:
        body += struct.pack("!HH", num, length)
    body += b"\x00" * pad
    return struct.pack("!HH", 0, 4 + len(body)) + body


def _v9_data_set(tid, payload):
    return struct.pack("!HH", tid, 4 + len(payload)) + payload


def test_single_pdu_and_stream_pdu_roundtrip():
    # Template 256: sourceIPv4Address (8, 4), packetDeltaCount (2, 4),
    #               flowStartSysUpTime (22, 4), flowEndSysUpTime (21, 4)
    tset = _v9_template_set(256, [(8, 4), (2, 4), (22, 4), (21, 4)], pad=2)
    rec1 = struct.pack("!4sLLL", ip_address("198.51.100.1").packed, 10, 50000, 55000)
    rec2 = struct.pack("!4sLLL", ip_address("198.51.100.2").packed, 20, 51000, 59000)
    dset = _v9_data_set(256, rec1 + rec2)
    pdu = _build_v9_pdu([tset, dset], reccount=2)

    # SinglePduBuffer
    sp = v9pdu.SinglePduBuffer(pdu)
    assert "PduBuffer" in repr(sp)
    recs = list(sp.namedict_iterator())
    assert len(recs) == 2
    assert recs[0]["sourceIPv4Address"] == ip_address("198.51.100.1")
    assert recs[0]["packetDeltaCount"] == 10
    assert list(sp.active_template_ids()) == [256]

    # Save / restore state
    state = sp.save_state()
    sp2 = v9pdu.SinglePduBuffer(_build_v9_pdu([dset], reccount=2))
    sp2.restore_state(state)
    ielist = ie.spec_list(["packetDeltaCount", "sourceIPv4Address"])
    tups = list(sp2.tuple_iterator(ielist))
    assert tups == [
        (10, ip_address("198.51.100.1")),
        (20, ip_address("198.51.100.2")),
    ]

    # StreamPduBuffer across two concatenated PDUs
    pdu2 = _build_v9_pdu([dset], reccount=2, sequence=2)
    stream = io.BytesIO(pdu + pdu2)
    sb = v9pdu.from_stream(stream)
    stream_recs = list(sb.namedict_iterator())
    assert len(stream_recs) == 4


def test_time_adapter_namedict_and_tuple():
    # export_epoch=1700000000, sysuptime_ms=60000 -> basetime=1699999940
    # flowStartSysUpTime=50000 -> 1699999990.0 (2023-11-14 22:13:10)
    # flowEndSysUpTime=55500 -> 1699999995.5 (2023-11-14 22:13:15.500000)
    tset = _v9_template_set(256, [(8, 4), (22, 4), (21, 4)])
    rec = struct.pack("!4sLL", ip_address("10.0.0.1").packed, 50000, 55500)
    pdu = _build_v9_pdu([tset, _v9_data_set(256, rec)])

    ta = v9pdu.TimeAdapter(v9pdu.SinglePduBuffer(pdu))
    recs = list(ta.namedict_iterator())
    assert len(recs) == 1
    assert recs[0]["flowStartMilliseconds"] == datetime(2023, 11, 14, 22, 13, 10, tzinfo=UTC)
    assert recs[0]["flowEndMilliseconds"] == datetime(2023, 11, 14, 22, 13, 15, 500000, tzinfo=UTC)

    # Tuple iterator with sysuptime fields
    ta2 = v9pdu.TimeAdapter(v9pdu.SinglePduBuffer(pdu))
    ielist = ie.spec_list(
        ["sourceIPv4Address", "flowStartSysUpTime", "flowEndSysUpTime"]
    )
    tups = list(ta2.tuple_iterator(ielist))
    assert len(tups) == 1
    assert tups[0][3] == datetime(2023, 11, 14, 22, 13, 10, tzinfo=UTC)
    assert tups[0][4] == datetime(2023, 11, 14, 22, 13, 15, 500000, tzinfo=UTC)

    # Tuple iterator without sysuptime fields passes through unchanged
    ta3 = v9pdu.TimeAdapter(v9pdu.SinglePduBuffer(pdu))
    tups3 = list(ta3.tuple_iterator(ie.spec_list(["sourceIPv4Address"])))
    assert tups3 == [(ip_address("10.0.0.1"),)]


def test_v9_malformed_inputs():
    # Short PDU
    with pytest.raises(IpfixDecodeError):
        v9pdu.SinglePduBuffer(b"\x00\x09\x00\x00")

    # Wrong version
    with pytest.raises(IpfixDecodeError):
        v9pdu.SinglePduBuffer(struct.pack("!HHLLLL", 10, 0, 0, 0, 0, 0))

    # Zero-length set (was infinite loop DoS!)
    bad_zero = _build_v9_pdu([struct.pack("!HH", 256, 0)])
    with pytest.raises(IpfixDecodeError):
        list(v9pdu.SinglePduBuffer(bad_zero).namedict_iterator())
    with pytest.raises(IpfixDecodeError):
        list(v9pdu.from_stream(io.BytesIO(bad_zero)).namedict_iterator())

    # Set extending past PDU
    bad_long = _build_v9_pdu([struct.pack("!HH", 256, 100)])
    with pytest.raises(IpfixDecodeError):
        list(v9pdu.SinglePduBuffer(bad_long).namedict_iterator())

    # Enterprise bit set in v9 template
    bad_pen = _build_v9_pdu([_v9_template_set(256, [(0x8001, 4)])])
    with pytest.raises(IpfixDecodeError):
        list(v9pdu.SinglePduBuffer(bad_pen).namedict_iterator())

    # Non-zero trailing bytes in v9 template set
    tbody = struct.pack("!HH HH", 256, 1, 8, 4) + b"\x01\x02"
    bad_pad = _build_v9_pdu([struct.pack("!HH", 0, 4 + len(tbody)) + tbody])
    with pytest.raises(IpfixDecodeError):
        list(v9pdu.SinglePduBuffer(bad_pad).namedict_iterator())

    # Truncated v9 set header in SinglePduBuffer
    with pytest.raises(IpfixDecodeError):
        list(v9pdu.SinglePduBuffer(_build_v9_pdu([b"\x01\x00"])).namedict_iterator())

    # StreamPduBuffer short PDU header, short set body, and EOF right after PDU header
    with pytest.raises(IpfixDecodeError):
        list(v9pdu.from_stream(io.BytesIO(b"\x00\x09\x00\x01\x00\x00")).namedict_iterator())
    with pytest.raises(IpfixDecodeError):
        list(
            v9pdu.from_stream(
                io.BytesIO(_build_v9_pdu([struct.pack("!HH", 256, 20) + b"\x00\x00"]))
            ).namedict_iterator()
        )
    assert list(v9pdu.from_stream(io.BytesIO(_build_v9_pdu([]))).namedict_iterator()) == []


def test_v9_hooks_and_illegal_setid():
    tset = _v9_template_set(256, [(8, 4)])
    dset = _v9_data_set(256, ip_address("10.0.0.1").packed)
    unk_set = _v9_data_set(300, b"\x01\x02\x03\x04")
    bad_set = struct.pack("!HH 4s", 100, 8, b"\x00\x00\x00\x00")
    pdu = _build_v9_pdu([tset, dset, unk_set, bad_set], reccount=2)

    headers = []
    unknown = []
    ignored = []
    sp = v9pdu.SinglePduBuffer(pdu)
    sp.message_header_hook = lambda p: headers.append(p.odid)
    sp.unknown_data_set_hook = lambda p, b: unknown.append(len(b))
    sp.ignored_data_set_hook = lambda p, t, b: ignored.append((t.tid, len(b)))
    # Re-parse header to exercise message_header_hook
    sp._parse_pdu_header()
    with pytest.warns(UserWarning, match="illegal set id 100"):
        assert list(sp.tuple_iterator(ie.spec_list(["packetDeltaCount"]))) == []
    assert headers == [42]
    assert unknown == [8]
    assert ignored == [(256, 8)]
