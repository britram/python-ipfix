# coding: utf8
#
# python-ipfix (c) 2013-2014 Brian Trammell.
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

from __future__ import unicode_literals, division
from . import ie, template, message, compat
from .template import IpfixEncodeError, IpfixDecodeError
from .compat import xrange
from datetime import datetime, timedelta
from ipaddress import ip_address
import base64
import io

_stored_test_message = base64.b64decode('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')

_test_strings = ["alfa", "bravo", "charlie", "delta", "echo", "foxtrot", "grüezi"]

def mktest_record(sequence):
    return { 'sourceIPv4Address': ip_address(0x7f000000 + sequence),
             'flowStartMilliseconds': datetime(2009, 2, 20, tzinfo=None) + timedelta(0, sequence / 1000),
             'testString': _test_strings[sequence % len(_test_strings)],
             'octetDeltaCount': sequence % 33,
             'packetDeltaCount': sequence % 27 }

def mktest_template(tid=257):
    ie.use_iana_default()
    ie.for_spec("testString(35566/32766)<string>")
    return template.from_ielist(tid,
           ie.spec_list(["sourceIPv4Address",
                         "flowStartMilliseconds",
                         "testString",
                         "octetDeltaCount[4]",
                         "packetDeltaCount"]))

def mktest_message(rec_count=128, odid=8304, tid=257):
    """
    Make a test message with a certain number of records.
    The test message contains a template with numeric, datetime,
    address, and string Information Elements, using both normal
    and reduced-length encoding.
    """

    msg = message.MessageBuffer()
    msg.begin_export(odid)
    msg.add_template(mktest_template(tid))
    msg.export_ensure_set(tid)
    msg.set_export_time(datetime(2009, 2, 20, 19, 18, 17, tzinfo=None))

    for seq in xrange(rec_count):
        msg.export_namedict(mktest_record(seq))

    return msg

def fuzzy_datetime_compare(a, b):
    # FIXME This is a hack. We should find a way to make datetimes export exactly
    return abs((a-b).total_seconds()) < 0.01

def msg_to_python(msg, varname="_stored_test_message"):
    return varname+' = base64.b64decode('+repr(base64.b64encode(msg.to_bytes()))+')'

def mktest_message_python(rec_count=128, odid=8304, tid=257, varname="_stored_test_message"):
    return msg_to_python(mktest_message(rec_count, odid, tid), varname=varname)

def test_stored_message():
    assert(_stored_test_message == mktest_message().to_bytes())

    msg = message.MessageBuffer()
    msg.from_bytes(_stored_test_message)
    for i, rec in enumerate(msg.namedict_iterator()):
        trec = mktest_record(i)
        assert(rec['packetDeltaCount'] == trec['packetDeltaCount'])
        assert(rec['octetDeltaCount'] == trec['octetDeltaCount'])
        assert(rec['sourceIPv4Address'] == trec['sourceIPv4Address'])
        assert(rec['testString'] == trec['testString'])
        assert(fuzzy_datetime_compare(rec['flowStartMilliseconds'], trec['flowStartMilliseconds']))

def test_message_write_internals():
    # make sure EOM works
    try:
        mktest_message(rec_count=65536)
        assert(False)
    except message.EndOfMessage as m:
        pass

def test_message_read_internals():
    msg = mktest_message()

    # test get_export_time
    assert(fuzzy_datetime_compare(msg.get_export_time(), datetime(2009, 2, 20, 19, 18, 17, tzinfo=None)))


def test_message_read_errors():
    short_read_test_message_hdr = bytearray(_stored_test_message)
    short_read_test_message_hdr = short_read_test_message_hdr[0:12]
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(short_read_test_message_hdr)
        assert(False)
    except IpfixDecodeError as e:
        pass

    short_read_test_message_body = bytearray(_stored_test_message)
    short_read_test_message_body = short_read_test_message_body[0:33]
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(short_read_test_message_body)
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_msg_version_test_message = bytearray(_stored_test_message)
    bad_msg_version_test_message[0] = 1
    bad_msg_version_test_message[1] = 2
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bad_msg_version_test_message)
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_msg_length_test_message = bytearray(_stored_test_message)
    bad_msg_length_test_message[2] = 0
    bad_msg_length_test_message[3] = 17
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bad_msg_length_test_message)
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_set_length_test_message_short = bytearray(_stored_test_message)
    bad_set_length_test_message_short[18] = 0
    bad_set_length_test_message_short[19] = 1
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bad_set_length_test_message_short)
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_set_length_test_message_long = bytearray(_stored_test_message)
    bad_set_length_test_message_long[18] = 255
    bad_set_length_test_message_long[19] = 255
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bad_set_length_test_message_long)
        assert(False)
    except IpfixDecodeError as e:
        pass
