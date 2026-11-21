import struct
from datetime import UTC, datetime
from ipaddress import ip_address

import pytest

import ipfix.ie as ie
import ipfix.message as message
import ipfix.template as template
import ipfix.testutils as testutils
from ipfix.template import IpfixDecodeError, IpfixEncodeError


@pytest.fixture(autouse=True)
def setup_iana():
    ie.clear_infomodel()
    ie.use_iana_default()
    yield
    ie.clear_infomodel()


def test_stored_message_roundtrip():
    generated = testutils.mktest_message().to_bytes()
    assert testutils._stored_test_message == generated

    msg = message.MessageBuffer()
    msg.from_bytes(testutils._stored_test_message)
    recs = list(msg.namedict_iterator())
    assert len(recs) == 128
    for i, rec in enumerate(recs):
        trec = testutils.mktest_record(i)
        assert rec["packetDeltaCount"] == trec["packetDeltaCount"]
        assert rec["octetDeltaCount"] == trec["octetDeltaCount"]
        assert rec["sourceIPv4Address"] == trec["sourceIPv4Address"]
        assert rec["testString"] == trec["testString"]
        assert testutils.fuzzy_datetime_compare(
            rec["flowStartMilliseconds"], trec["flowStartMilliseconds"]
        )


def test_varlen_first_ie_issue24():
    """Regression test for Issue #24 / PR #25 / PR #30: varlen as first IE."""
    tmpl = template.for_specs(
        256,
        "applicationName",
        "flowStartMilliseconds",
        "sourceIPv4Address",
        "packetDeltaCount",
    )
    assert tmpl.varlenslice == 0

    msg = message.MessageBuffer()
    msg.begin_export(8304)
    msg.add_template(tmpl)
    msg.export_ensure_set(256)

    long_name = "x" * 300  # also exercises 255-byte extended varlen encoding
    rec_in = {
        "applicationName": long_name,
        "flowStartMilliseconds": datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC),
        "sourceIPv4Address": ip_address("10.1.2.3"),
        "packetDeltaCount": 99,
    }
    msg.export_namedict(rec_in)
    raw = msg.to_bytes()

    msg2 = message.MessageBuffer()
    msg2.from_bytes(raw)
    recs = list(msg2.namedict_iterator())
    assert len(recs) == 1
    assert recs[0] == rec_in

    # Tuple iterator with varlen first IE
    ielist = ie.spec_list(["packetDeltaCount", "applicationName"])
    tups = list(msg2.tuple_iterator(ielist))
    assert tups == [(99, long_name)]


def test_template_set_padding_pr30():
    """RFC 7011 §3.3.1: zero alignment padding at the end of a Template Set."""
    tmpl = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")
    for pad_len in (1, 2, 3, 4, 6):
        # Build a message with a Template Set padded with pad_len zero bytes
        tbuf = bytearray(64)
        toff = tmpl.encode_template_to(tbuf, 0, template.TEMPLATE_SET_ID)
        tset_body = bytes(tbuf[:toff]) + (b"\x00" * pad_len)
        tset = struct.pack("!HH", template.TEMPLATE_SET_ID, 4 + len(tset_body)) + tset_body
        raw = struct.pack("!HHLLL", 10, 16 + len(tset), 1700000000, 0, 1) + tset

        msg = message.MessageBuffer()
        msg.from_bytes(raw)
        assert list(msg.namedict_iterator()) == []
        assert (1, 256) in msg.templates

    # Non-zero trailing bytes (< 4 bytes) must raise IpfixDecodeError
    tbuf = bytearray(64)
    toff = tmpl.encode_template_to(tbuf, 0, template.TEMPLATE_SET_ID)
    tset_body = bytes(tbuf[:toff]) + b"\x00\x01"
    tset = struct.pack("!HH", template.TEMPLATE_SET_ID, 4 + len(tset_body)) + tset_body
    raw = struct.pack("!HHLLL", 10, 16 + len(tset), 1700000000, 0, 1) + tset
    msg = message.MessageBuffer()
    msg.from_bytes(raw)
    with pytest.raises(IpfixDecodeError):
        list(msg.namedict_iterator())


def test_template_withdrawal_export_and_decode():
    tmpl = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")
    msg = message.MessageBuffer()
    msg.begin_export(42)
    msg.add_template(tmpl)
    msg.export_ensure_set(256)
    msg.export_namedict(
        {"sourceIPv4Address": ip_address("192.0.2.1"), "packetDeltaCount": 5}
    )
    msg.delete_template(256, export=True)
    raw = msg.to_bytes()

    # Decode: data set decoded before withdrawal, template removed after withdrawal
    seen_templates = []
    msg2 = message.MessageBuffer()
    msg2.template_record_hook = lambda m, t: seen_templates.append((t.tid, t.count()))
    msg2.from_bytes(raw)
    recs = list(msg2.namedict_iterator())
    assert len(recs) == 1
    assert (42, 256) not in msg2.templates
    assert seen_templates == [(256, 2), (256, 0)]

    # All-Templates Withdrawal (TID == 2, count == 0)
    msg3 = message.MessageBuffer()
    msg3.begin_export(42)
    msg3.add_template(template.for_specs(256, "sourceIPv4Address"))
    msg3.add_template(template.for_specs(257, "packetDeltaCount"))
    msg3._export_template_withdrawal(template.TEMPLATE_SET_ID, template.TEMPLATE_SET_ID)
    raw_all = msg3.to_bytes()

    msg4 = message.MessageBuffer()
    msg4.from_bytes(raw_all)
    assert list(msg4.namedict_iterator()) == []
    assert list(msg4.active_template_ids()) == []


def test_options_template_and_validation():
    otmpl = template.for_specs(260, "observationDomainId", "octetDeltaCount", scopecount=1)
    assert otmpl.native_setid() == template.OPTIONS_SET_ID

    msg = message.MessageBuffer()
    msg.begin_export(7)
    msg.add_template(otmpl)
    msg.export_ensure_set(260)
    msg.export_namedict({"observationDomainId": 7, "octetDeltaCount": 1234})
    raw = msg.to_bytes()

    msg2 = message.MessageBuffer()
    msg2.from_bytes(raw)
    recs = list(msg2.namedict_iterator())
    assert recs == [{"observationDomainId": 7, "octetDeltaCount": 1234}]
    assert msg2.template_for_id(260).scopecount == 1

    # Invalid options template: scopecount == 0 with count > 0
    bad_oset = struct.pack("!HH HHH HH", 3, 14, 261, 1, 0, 1, 8)
    bad_msg = struct.pack("!HHLLL", 10, 16 + len(bad_oset), 1700000000, 0, 7) + bad_oset
    msg3 = message.MessageBuffer()
    msg3.from_bytes(bad_msg)
    with pytest.raises(IpfixDecodeError):
        list(msg3.namedict_iterator())


def test_template_identical_to_checks_length():
    t1 = template.for_specs(256, "octetDeltaCount")
    t2 = template.for_specs(257, "octetDeltaCount[4]")
    t3 = template.for_specs(258, "octetDeltaCount")
    assert not t1.identical_to(t2)
    assert t1.identical_to(t3)


def test_begin_export_odid_zero_and_sequence_wrap():
    msg = message.MessageBuffer()
    msg.begin_export(100)
    assert msg.odid == 100
    msg.sequences[(0, 0)] = 0xFFFFFFFF
    msg.begin_export(0)
    assert msg.odid == 0
    assert msg.sequence == 0xFFFFFFFF
    msg._increment_sequence()
    assert msg.sequences[(0, 0)] == 0


def test_hooks_and_unknown_ignored_sets():
    t1 = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")
    msg = message.MessageBuffer()
    msg.begin_export(1)
    msg.add_template(t1)
    msg.export_ensure_set(256)
    msg.export_namedict(
        {"sourceIPv4Address": ip_address("10.0.0.1"), "packetDeltaCount": 1}
    )
    raw = msg.to_bytes()

    headers = []
    ignored = []
    msg2 = message.MessageBuffer()
    msg2.message_header_hook = lambda m: headers.append(m.odid)
    msg2.ignored_data_set_hook = lambda m, t, b: ignored.append((t.tid, len(b)))
    msg2.from_bytes(raw)
    # Request an IE not in template 256 -> ignored_data_set_hook called
    assert list(msg2.tuple_iterator(ie.spec_list(["destinationIPv4Address"]))) == []
    assert headers == [1]
    assert len(ignored) == 1 and ignored[0][0] == 256

    # Unknown data set (no template 300)
    dset = struct.pack("!HH4s", 300, 8, b"\x01\x02\x03\x04")
    raw_unk = struct.pack("!HHLLL", 10, 16 + len(dset), 1700000000, 0, 1) + dset
    unknown = []
    msg3 = message.MessageBuffer()
    msg3.unknown_data_set_hook = lambda m, b: unknown.append(len(b))
    msg3.from_bytes(raw_unk)
    assert list(msg3.namedict_iterator()) == []
    assert unknown == [8]


def test_malformed_packet_security_dos_cases():
    # 1. setlen == 0 (was infinite loop DoS!)
    raw = struct.pack("!HHLLL HH", 10, 20, 0, 0, 0, 256, 0)
    with pytest.raises(IpfixDecodeError):
        message.MessageBuffer().from_bytes(raw)

    # 2. setlen == 3 (< 4)
    raw = struct.pack("!HHLLL HH", 10, 20, 0, 0, 0, 256, 3)
    with pytest.raises(IpfixDecodeError):
        message.MessageBuffer().from_bytes(raw)

    # 3. Truncated set header at end of message (2 trailing bytes)
    tset = struct.pack("!HH", 2, 4)
    raw = struct.pack("!HHLLL", 10, 22, 0, 0, 0) + tset + b"\x00\x00"
    with pytest.raises(IpfixDecodeError):
        message.MessageBuffer().from_bytes(raw)

    # 4. Zero-length IE in template
    tset = struct.pack("!HH HH HH", 2, 12, 256, 1, 1, 0)
    raw = struct.pack("!HHLLL", 10, 16 + len(tset), 0, 0, 0) + tset
    msg = message.MessageBuffer()
    msg.from_bytes(raw)
    with pytest.raises(IpfixDecodeError):
        list(msg.namedict_iterator())

    # 5. Truncated enterprise PEN in template
    tset = struct.pack("!HH HH HH", 2, 12, 256, 1, 0x8001, 4)
    raw = struct.pack("!HHLLL", 10, 16 + len(tset), 0, 0, 0) + tset
    msg = message.MessageBuffer()
    msg.from_bytes(raw)
    with pytest.raises(IpfixDecodeError):
        list(msg.namedict_iterator())

    # 6. Varlen length extending past setend (previously leaked stale mbuf bytes!)
    tset = struct.pack("!HH HH HH", 2, 12, 256, 1, 96, 65535)  # applicationName varlen
    dset = struct.pack("!HH B 2s", 256, 7, 200, b"hi")  # claims 200 bytes, only 2 present
    raw = struct.pack("!HHLLL", 10, 16 + len(tset) + len(dset), 0, 0, 0) + tset + dset
    msg = message.MessageBuffer()
    msg.from_bytes(raw)
    with pytest.raises(IpfixDecodeError):
        list(msg.namedict_iterator())

    # 7. Template with minlength == 0 manually injected must not infinite-loop
    msg = message.MessageBuffer()
    empty_t = template.Template(256)
    empty_t.finalize()
    msg.templates[(0, 256)] = empty_t
    msg.accepted_tids.add((0, 256))
    dset = struct.pack("!HH4s", 256, 8, b"\x00\x00\x00\x00")
    raw = struct.pack("!HHLLL", 10, 16 + len(dset), 0, 0, 0) + dset
    msg.from_bytes(raw)
    with pytest.raises(IpfixDecodeError):
        list(msg.namedict_iterator())


def test_message_read_errors_and_eom():
    # Short header, short body, bad version, bad length, bad set length
    stored = testutils._stored_test_message
    for bad in (
        stored[:12],
        stored[:33],
        b"\x01\x02" + stored[2:],
        stored[:2] + b"\x00\x11" + stored[4:],
        stored[:18] + b"\x00\x01" + stored[20:],
        stored[:18] + b"\xff\xff" + stored[20:],
    ):
        with pytest.raises(IpfixDecodeError):
            message.MessageBuffer().from_bytes(bad)

    # EOM on record overflow
    with pytest.raises(message.EndOfMessage):
        testutils.mktest_message(rec_count=65536)

    # MTU too small
    msg = message.MessageBuffer()
    msg.mtu = 10
    with pytest.raises(IpfixEncodeError):
        msg.begin_export(1)

    # Start set without template
    msg = message.MessageBuffer()
    msg.begin_export(1)
    with pytest.raises(IpfixEncodeError):
        msg.export_new_set(999)

    # withdrawal_length raises (not returns) on bad set id
    with pytest.raises(IpfixEncodeError):
        template.withdrawal_length(99)
    with pytest.raises(IpfixEncodeError):
        template.encode_withdrawal_to(bytearray(16), 0, 99, 256)


def test_unsigned256_in_message_roundtrip():
    tmpl = template.for_specs(256, "tcpOptionsFull", "udpSafeOptions")
    msg = message.MessageBuffer()
    msg.begin_export(1)
    msg.add_template(tmpl)
    msg.export_ensure_set(256)
    rec = {
        "tcpOptionsFull": (1 << 255) | (1 << 128) | 1,
        "udpSafeOptions": (1 << 200) | 0x42,
    }
    msg.export_namedict(rec)
    raw = msg.to_bytes()

    msg2 = message.MessageBuffer()
    msg2.from_bytes(raw)
    assert list(msg2.namedict_iterator()) == [rec]
