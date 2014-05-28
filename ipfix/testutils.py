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

from . import ie, template, message
from .template import IpfixEncodeError, IpfixDecodeError
from datetime import datetime, timedelta
from ipaddress import ip_address
import base64
import io

_stored_test_message =     base64.b85decode(b'016L#00000NuL4v001Cx00ICY0RaF700;mC0GI#>|Nj5~004^a0096500ICA0Raz7e*gdg0003Wko!ac1YvAuVE_OC00000000000Dk}g0RR92ACUV*0R>`mVRml-00031000000004h0006200AG6`$Pf<V`yP=Y-wcx00062000000007i0009300AG6`$Pi;WMyo0VE_OC0{{R3000001AhPj1ONa5ACUV*1O#PcXm0=j00aO40000000e&k00jU50Uwb2L<I+CZ+LWaZ*%|v00jU50000000n;l00sa60Uwb2L<R?Ea>Kl3dT9Uv00sa60000000w^m00#g70Uwb2L<a<6Y-V8q000L700000000Mn000O800AG6`$Px@Vsc@2ZvX%Q2mk;8000002!8+o2><{AACUV*2?t|nVRCF~WdHyG2><{90000034Z_p3IG5BACUV*3I$|kY;<7&000UA00000000Vq000XB00AG6`$P)_Wn*Y>0000B000000000Be*gds0003Wko!ao2WD@0baHQW0000C000000000Ce*gdt0003Wko!ap2WN7_yk&Z60000D000000000De*gdu0003Wko!aq1YvAuVE_OC4gdfE000004u1du4*&oGACUV*4+Ua!VRml-000jF00000000kv000mG00AG6`$P~2V`yP=Y-wcx000mG00000000nw000pH00AG6`$Q21WMyo0VE_OC5dZ)H000005q|&x5&!@JACUV*5(H&qXm0=j01^NI0000001|%y022TJ0Uwb2L=y*QZ+LWaZ*%|v022TJ00000026-z02BZK0Uwb2L=*>Sa>Kl3dT9Uv02BZK0000002F@!02KfL0Uwb2L=^;KY-V8q000#L00000000$#000&M00AG6`$QH6Vsc@2ZvX%Q761SM000007JmQ$7XSbOACUV*7YAc#VRCF~WdHyG7XSbN000007k>Z%7ytkPACUV*7zJcyY;<7&000;O00000000<&000>P00AG6`$QQ8Wn*Y>0000P000000000Pe*gd)0003Wko!a$2WD@0baHQW0000Q000000000Qe*gd*0003Wko!a%2WN7_yk&Z60000R0000000000e*gd+0003Wko!a&1YvAuVE_OC8~^|S000000e=7h9RL6UACUV*9R*@?VRml-0012T000000007i0015U00AG6`$QfGV`yP=Y-wcx0015U00000000Aj0018V00AG6`$QiFWMyo0VE_OC9{>OV000001b+YkAOHXXACUV*AOvM&Xm0=j03ZMW0000000n;l03iSX0Uwb2L?H)eZ+LWaZ*%|v000000000000w^m03rYY0Uwb2L?Q=ga>Kl3dT9Uv009610000000(~n03!eZ0Uwb2L?Z-YY-V8q0006200000000Po001Na00AG6`$QxKVsc@2ZvX%Q0{{R30000034Z_pB>(^cACUV*B?n_@VRCF~WdHyG1ONa4000003V#3qCIA2dACUV*CIw_=Y;<7&000F500000000Yr001Wd00AG6`$Q)MWn*Y>00006000000000Ce*gd|0003Wko!a^2WD@0baHQW00007000000000De*gd}0003Wko!a_2WN7_yk&Z600008000000000Ee*gd~0003Wko!a`1YvAuVE_OC2><{9000004}SmvD*yliACUV*D+OY5VRml-000UA00000000nw001li00AG6`$Q}UV`yP=Y-wcx000XB00000000qx001oj00AG6`$R1TWMyo0VE_OC3;+NC000005`O>yE&u=lACUV*E(B#`Xm0=j01W^D00000026-z051Rl0Uwb2L@x(sZ+LWaZ*%|v01f~E0000002F@!05AXm0Uwb2L@)<ua>Kl3dT9Uv01p5F0000002O}#05Jdn0Uwb2L@@+mY-V8q000mG00000000($001%o00AG6`$RGYVsc@2ZvX%Q5dZ)H000007k>Z%GXMYqACUV*GY4a6VRCF~WdHyG5&!@I000007=Hi&GynhrACUV*GzDa3Y;<7&000vJ00000000?(001=r00AG6`$RPaWn*Y>0000K000000000Qe*geB0003Wko!b72WD@0baHQW0000L0000000000e*geC0003Wko!b82WN7_yk&Z60000M0000000001e*geD0003Wko!b91YvAuVE_OC7XSbN000000)GGiIRF3wACUV*IR#>JVRml-000;O00000000Aj0024w00AG6`$ReiV`yP=Y-wcx000>P00000000Dk0027x00AG6`$RhhWMyo0VE_OC8UO$Q000001%ChlJOBUzACUV*JOpK9Xm0=j02=@R0000000w^m06hQz0Uwb2L_G&)Z+LWaZ*%|v02}}S0000000(~n06qW!0Uwb2L_P;+a>Kl3dT9Uv0384T0000000@5o06zc#0Uwb2L_Y*!Y-V8q0015U00000000Sp002M$00AG6`$RwmVsc@2ZvX%Q9{>OV000003V#3qK>z>&ACUV*K?h@KVRCF~WdHyGAOHXW000003x5CrLI3~(ACUV*LIq@HY;<7&0000000000000bs002V(00AG6`$R(oWn*Y>00001000000000De*geP0003Wko!bL2WD@0baHQW00002000000000Ee*geQ0003Wko!bM2WN7_yk&Z600003000000000Fe*geR0003Wko!bN1YvAuVE_OC1ONa4000005PtvwM*si;ACUV*M+IVXVRml-000F500000000qx002k;00AG6`$R|wV`yP=Y-wcx000I600000000ty002n<00AG6`$S0vWMyo0VE_OC2LJ#7000006Mp~zN&o->ACUV*N(5zNXm0=j00;m80000002F@!080P>0Uwb2L`w%|Z+LWaZ*%|v00{s90000002O}#089V?0Uwb2L`(-~a>Kl3dT9Uv015yA0000002Y4$08Ib@0Uwb2L`?)?Y-V8q000XB00000000+%002$^00AG6`$SF!Vsc@2ZvX%Q3;+NC000007=Hi&PXGV`ACUV*PX}XYVRCF~WdHyG4FCWD000008Gir(Pyhe{ACUV*Pz7XVY;<7&000gE00000000_)002<{00AG6`$SO$Wn*Y>0000F0000000000e*ged0003Wko!bZ2WD@0baHQW0000G0000000001e*gee0003Wko!ba2WN7_yk&Z60000H0000000002e*gef0003Wko!bb1YvAuVE_OC5&!@I000001AhPjRR911ACUV*RRv;lVRml-000vJ00000000Dk0034100AG6`$Sd;V`yP=Y-wcx000yK00000000Gl0037200AG6`$Sg-WMyo0VE_OC6#xJL0000027dqmSO5S4ACUV*SOjHbXm0=j02TlM0000000(~n09gP40Uwb2L|F%BZ+LWaZ*%|v02crN0000000@5o09pV50Uwb2L|O-Da>Kl3dT9Uv02lxO00000011Bp09yb60Uwb2L|X)5Y-V8q000>P00000000Vq003M700AG6`$Sv?Vsc@2ZvX%Q8UO$Q000003x5CrT>t<9ACUV*T?b=mVRCF~WdHyG8vp<R0000041WLsUH||AACUV*UIk=jY;<7&000~S00000000et003VA00AG6`$S&^Wn*Y>0000T000000000Ee*ger0003Wko!bn2WD@0baHQW0000U000000000Fe*ges0003Wko!bo2WN7_yk&Z60000V000000000Ge*get0003Wko!bp1YvAuVE_OCAOHXW000005q|&xV*mgFACUV*V+CSzVRml-0000000000000ty003kF00AG6`$S|1V`yP=Y-wcx0003100000000wz003nG00AG6`$T00WMyo0VE_OC0ssI2000006n_8!W&i*IACUV*W&~wpXm0=j00RI30000002O}#0A~OI0Uwb2L}v$PZ+LWaZ*%|v00aO40000002Y4$0B8UJ0Uwb2L}&+Ra>Kl3dT9Uv00jU50000002hA%0BHaK0Uwb2L}>(JY-V8q000I600000000<&003$L00AG6`$TF5Vsc@2ZvX%Q2LJ#7000008Gir(YXATNACUV*YX@U!VRCF~WdHyG2mk;8000008h-!)YybcOACUV*Yz1UxY;<7&000R9000000001g003<O00AG6`$TO7Wn*Y>0000A0000000001e*ge(0003Wko!b#2WD@0baHQW0000B0000000002e*ge)0003Wko!b$2WN7_yk&Z60000C0000000003e*ge*0003Wko!b%1YvAuVE_OC4FCWD000001b+YkaR2}TACUV*aRp*>VRml-000gE00000000Gl0043T00AG6`$TdFV`yP=Y-wcx000jF00000000Jm0046U00AG6`$TgEWMyo0VE_OC5C8xG000002Y&znbN~PWACUV*bOdE%Xm0=j01*HH0000000@5o0CfNW0Uwb2M0E#dZ+LWaZ*%|v01^NI00000011Bp0CoTX0Uwb2M0N*fa>Kl3dT9Uv022TJ0000001AHq0CxZY0Uwb2M0W&XY-V8q000yK00000000Yr004LZ00AG6`$TvJVsc@2ZvX%Q6#xJL0000041WLsc>n+bACUV*c?V-?VRCF~WdHyG761SM000004SxUtdH?_cACUV*dIe-<Y;<7&000*N00000000hu004Uc00AG6`$T&LWn*Y>0000O000000000Fe*ge{0003Wko!b@2WD@0baHQW0000P000000000Ge*ge|0003Wko!b^2WN7_yk&Z60000Q000000000He*ge}0003Wko!b_1YvAuVE_OC8vp<R000005`O>ye*gdhACUV*e+6Q4VRml-000~S00000000v')

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

    for seq in range(rec_count):
        msg.export_namedict(mktest_record(seq))

    return msg

def fuzzy_datetime_compare(a, b):
    # FIXME This is a hack. We should find a way to make datetimes export exactly
    return abs((a-b).total_seconds()) < 0.01

def msg_to_python(msg, varname="_stored_test_message"):
    return varname+' = base64.b85decode('+repr(base64.b85encode(msg.to_bytes()))+')'

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
        msg.from_bytes(bytes(short_read_test_message_hdr))
        assert(False)
    except IpfixDecodeError as e:
        pass

    short_read_test_message_body = bytearray(_stored_test_message)
    short_read_test_message_body = short_read_test_message_body[0:33]
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bytes(short_read_test_message_body))
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_msg_version_test_message = bytearray(_stored_test_message)
    bad_msg_version_test_message[0] = 1
    bad_msg_version_test_message[1] = 2
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bytes(bad_msg_version_test_message))
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_msg_length_test_message = bytearray(_stored_test_message)
    bad_msg_length_test_message[2] = 0
    bad_msg_length_test_message[3] = 17
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bytes(bad_msg_length_test_message))
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_set_length_test_message_short = bytearray(_stored_test_message)
    bad_set_length_test_message_short[18] = 0
    bad_set_length_test_message_short[19] = 1
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bytes(bad_set_length_test_message_short))
        assert(False)
    except IpfixDecodeError as e:
        pass

    bad_set_length_test_message_long = bytearray(_stored_test_message)
    bad_set_length_test_message_long[18] = 255
    bad_set_length_test_message_long[19] = 255
    msg = message.MessageBuffer()
    try:
        msg.from_bytes(bytes(bad_set_length_test_message_long))
        assert(False)
    except IpfixDecodeError as e:
        pass



