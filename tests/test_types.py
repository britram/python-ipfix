import ipaddress
import struct
from datetime import UTC, datetime, timedelta, timezone

import pytest

import ipfix.types as types


def test_for_name_unknown():
    with pytest.raises(types.IpfixTypeError):
        types.for_name("bogus")


def test_exception_subclassable():
    class SubTypeError(types.IpfixTypeError):
        pass

    err = SubTypeError("boom")
    assert isinstance(err, types.IpfixTypeError)
    assert str(err) == "boom"


def test_all_builtin_types_roundtrip():
    buf = memoryview(bytearray(64))
    dt = datetime(2024, 5, 6, 7, 8, 9, 123000, tzinfo=UTC)

    cases = [
        ("octetArray", b"\xde\xad\xbe\xef", b"\xde\xad\xbe\xef"),
        ("unsigned8", 255, 255),
        ("unsigned16", 65535, 65535),
        ("unsigned32", 2**32 - 1, 2**32 - 1),
        ("unsigned64", 2**64 - 1, 2**64 - 1),
        ("unsigned256", (1 << 255) | 0xCAFEBABE, (1 << 255) | 0xCAFEBABE),
        ("signed8", -128, -128),
        ("signed16", -32768, -32768),
        ("signed32", -(2**31), -(2**31)),
        ("signed64", -(2**63), -(2**63)),
        ("float32", 3.5, 3.5),
        ("float64", 3.141592653589793, 3.141592653589793),
        ("boolean", True, True),
        ("boolean", False, False),
        ("macAddress", b"\x00\x11\x22\x33\x44\x55", b"\x00\x11\x22\x33\x44\x55"),
        ("string", "hello Grüezi", "hello Grüezi"),
        ("dateTimeSeconds", dt, datetime(2024, 5, 6, 7, 8, 9, tzinfo=UTC)),
        ("dateTimeMilliseconds", dt, dt),
        ("dateTimeMicroseconds", dt, dt),
        ("dateTimeNanoseconds", dt, dt),
        (
            "ipv4Address",
            ipaddress.ip_address("192.0.2.1"),
            ipaddress.ip_address("192.0.2.1"),
        ),
        (
            "ipv6Address",
            ipaddress.ip_address("2001:db8::1"),
            ipaddress.ip_address("2001:db8::1"),
        ),
    ]

    for tname, val, expected in cases:
        t = types.for_name(tname)
        end = t.encode_single_value_to(val, buf, 0)
        got = t.decode_single_value_from(buf, 0, end)
        assert got == expected, f"Mismatch for {tname}: {got!r} != {expected!r}"


def test_rle_power_of_two_and_arbitrary_widths():
    buf = memoryview(bytearray(64))

    # Power-of-two RLE
    u64_2 = types.for_name("unsigned64").for_length(2)
    assert u64_2.length == 2
    end = u64_2.encode_single_value_to(0x1234, buf, 0)
    assert end == 2
    assert u64_2.decode_single_value_from(buf, 0, 2) == 0x1234
    # Regression: valstr and valparse preserved on RLE types
    assert u64_2.valstr(42) == "42"
    assert u64_2.valparse("42") == 42

    # Non-power-of-two RLE (RFC 7011 §6.2)
    u32_3 = types.for_name("unsigned32").for_length(3)
    end = u32_3.encode_single_value_to(0xABCDEF, buf, 0)
    assert end == 3
    assert u32_3.decode_single_value_from(buf, 0, 3) == 0xABCDEF

    s32_3 = types.for_name("signed32").for_length(3)
    end = s32_3.encode_single_value_to(-123456, buf, 0)
    assert end == 3
    assert s32_3.decode_single_value_from(buf, 0, 3) == -123456

    u256_16 = types.for_name("unsigned256").for_length(16)
    val = (1 << 120) + 7
    end = u256_16.encode_single_value_to(val, buf, 0)
    assert end == 16
    assert u256_16.decode_single_value_from(buf, 0, 16) == val

    f64_4 = types.for_name("float64").for_length(4)
    end = f64_4.encode_single_value_to(1.5, buf, 0)
    assert end == 4
    assert f64_4.decode_single_value_from(buf, 0, 4) == 1.5

    # Invalid RLE lengths
    with pytest.raises(types.IpfixTypeError):
        types.for_name("unsigned16").for_length(4)
    with pytest.raises(types.IpfixTypeError):
        types.for_name("ipv4Address").for_length(2)
    with pytest.raises(types.IpfixTypeError):
        types.for_name("unsigned32").for_length(types.VARLEN)
    with pytest.raises(types.IpfixTypeError):
        types.for_name("octetArray").for_length(-1)


def test_fixed_length_string_and_octet_array():
    buf = memoryview(bytearray(32))

    # Fixed-length string: trailing NUL padding stripped on decode (Issue #21)
    s14 = types.for_name("string").for_length(14)
    end = s14.encode_single_value_to("ietf-a-v6only", buf, 0)
    assert end == 14
    assert bytes(buf[:14]) == b"ietf-a-v6only\x00"
    assert s14.decode_single_value_from(buf, 0, 14) == "ietf-a-v6only"
    assert s14.valstr("abc") == "abc"
    assert s14.valparse("abc") == "abc"

    # Re-sizing fixed-length string
    s16 = s14.for_length(16)
    assert s16.length == 16

    # Oversized UTF-8 string raises ValueError instead of silent mid-codepoint truncation
    s4 = types.for_name("string").for_length(4)
    with pytest.raises(ValueError):
        s4.encode_single_value_to("Grüezi", buf, 0)

    # Fixed-length octetArray + re-sizing
    oa4 = types.for_name("octetArray").for_length(4)
    assert oa4.length == 4
    oa8 = oa4.for_length(8)
    assert oa8.length == 8
    assert oa8.valstr(b"\xab") == b"ab"


def test_boolean_validation_and_str():
    buf = memoryview(bytearray(4))
    btype = types.for_name("boolean")
    buf[0] = 3
    with pytest.raises(ValueError):
        btype.decode_single_value_from(buf, 0, 1)

    assert btype.valstr(True) == "true"
    assert btype.valstr(False) == "false"
    assert btype.valparse("true") is True
    assert btype.valparse("false") is False


def test_use_integer_ipv4_and_restore():
    buf = memoryview(bytearray(4))
    try:
        types.use_integer_ipv4()
        t = types.for_name("ipv4Address")
        end = t.encode_single_value_to(0xC0000201, buf, 0)
        assert end == 4
        assert t.decode_single_value_from(buf, 0, 4) == 0xC0000201
    finally:
        types.use_ipaddress_ipv4()

    t = types.for_name("ipv4Address")
    assert t.decode_single_value_from(buf, 0, 4) == ipaddress.IPv4Address("192.0.2.1")


def test_datetime_aware_and_naive_encode_and_parse():
    buf = memoryview(bytearray(8))
    naive = datetime(2024, 6, 15, 12, 30, 45, 500000)
    aware_utc = datetime(2024, 6, 15, 12, 30, 45, 500000, tzinfo=UTC)
    aware_plus2 = datetime(
        2024, 6, 15, 14, 30, 45, 500000, tzinfo=timezone(timedelta(hours=2))
    )

    for tname in ("dateTimeSeconds", "dateTimeMilliseconds", "dateTimeMicroseconds"):
        t = types.for_name(tname)
        t.encode_single_value_to(naive, buf, 0)
        b_naive = bytes(buf[: t.length])
        t.encode_single_value_to(aware_utc, buf, 0)
        b_utc = bytes(buf[: t.length])
        t.encode_single_value_to(aware_plus2, buf, 0)
        b_plus2 = bytes(buf[: t.length])
        assert b_naive == b_utc == b_plus2

        decoded = t.decode_single_value_from(buf, 0, t.length)
        assert decoded.tzinfo is UTC

    # ISO 8601 parse/unparse with Z and offset (returns aware UTC in 1.0.0)
    assert types.for_name("dateTimeSeconds").valparse("2024-06-15T12:30:45Z") == datetime(
        2024, 6, 15, 12, 30, 45, tzinfo=UTC
    )
    assert types.for_name("dateTimeMilliseconds").valparse(
        "2024-06-15 12:30:45.123+00:00"
    ) == datetime(2024, 6, 15, 12, 30, 45, 123000, tzinfo=UTC)
    assert types.for_name("dateTimeMicroseconds").valparse(
        "2024-06-15 12:30:45.123456Z"
    ) == datetime(2024, 6, 15, 12, 30, 45, 123456, tzinfo=UTC)
    assert types.for_name("dateTimeSeconds").valstr(naive) == "2024-06-15 12:30:45"
    assert (
        types.for_name("dateTimeMilliseconds").valstr(naive)
        == "2024-06-15 12:30:45.500"
    )
    assert (
        types.for_name("dateTimeMicroseconds").valstr(naive)
        == "2024-06-15 12:30:45.500000"
    )


def test_ntp_era1_2036_rollover():
    """RFC 5905 NTP Era 1 rollover (2036-02-07 06:28:16 UTC) round-trips cleanly."""
    buf = memoryview(bytearray(8))
    t = types.for_name("dateTimeMicroseconds")

    for dt in (
        datetime(2036, 2, 7, 6, 28, 15, 500000, tzinfo=UTC),  # just before rollover
        datetime(2036, 2, 7, 6, 28, 16, 0, tzinfo=UTC),       # exact rollover (Era 1)
        datetime(2036, 2, 7, 6, 28, 17, 123456, tzinfo=UTC),  # just after rollover
        datetime(2050, 1, 1, 0, 0, 0, 250000, tzinfo=UTC),    # mid Era 1
    ):
        end = t.encode_single_value_to(dt, buf, 0)
        assert end == 8
        got = t.decode_single_value_from(buf, 0, 8)
        assert got.tzinfo is UTC
        assert abs((got - dt).total_seconds()) < 1e-5


def test_varlen_encode_decode_and_bounds():
    buf = memoryview(bytearray(16))

    off = types.encode_varlen(buf, 0, 10)
    assert off == 1
    assert types.decode_varlen(buf, 0) == (10, 1)

    off = types.encode_varlen(buf, 0, 255)
    assert off == 3
    assert types.decode_varlen(buf, 0) == (255, 3)

    off = types.encode_varlen(buf, 0, 1024)
    assert off == 3
    assert types.decode_varlen(buf, 0) == (1024, 3)

    # Truncated varlen prefix
    with pytest.raises(struct.error):
        types.decode_varlen(buf, 0, end=0)
    with pytest.raises(struct.error):
        types.decode_varlen(buf, 0, end=2)  # 255 prefix needs 3 bytes


def test_type_ordering_and_length_mismatch():
    u8 = types.for_name("unsigned8")
    u16 = types.for_name("unsigned16")
    assert u8 < u16
    assert str(u8) == "<unsigned8>"
    assert repr(u8) == "ipfix.types.for_name('unsigned8')"

    buf = memoryview(bytearray(4))
    with pytest.raises(types.IpfixTypeError):
        u16.decode_single_value_from(buf, 0, 4)
