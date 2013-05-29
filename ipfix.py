import re
from datetime import datetime, timedelta
from ipaddress import ip_address
from struct import Struct
from functools import total_ordering

# precompiled module variables (parsers)
_iespec_re = re.compile('^([^\s\[\<\(]+)?(\(((\d+)\/)?(\d+)\))?(\<(\S+)\>)?(\[(\S+)\])?')

_sethdr_st = Struct("!HH")
_msghdr_st = Struct("!HHLLL")
_tmplhdr_st = Struct("!HH")
_otmplhdr_st = Struct("!HHH")
_iespec_st = Struct("!HH")
_iepen_st = Struct("!L")

# constants
Varlen = 65535

# Builtin exception

class IPFIXDecodeError(Exception):
    def __init__(self, *args):
        super().__init__(args)

# Builtin type implementation

class IpfixType:
    """docstring for IpfixType"""
    def __init__(self, name, num):
        self.name = name
        self.num = num
    
    def __str__(self):
        return "<%s>" % self.name
        
    def __repr__(self):
        return "_TypeForName[%s]" % repr(self.name)
        
    def length(self):
        return 0;
    
    def decode_value_from(self, buf, offset, length):
        raise NotImplementedException()
    
    def encode_value_to(self, val, buf, offset, length):
        raise NotImplementedException()    


class BytesType(IpfixType):
    """docstring for BytesType"""
    def __init__(self, name, num, length):
        super().__init__(name, num)
        self.length = length;
        
    def length(self):
        return self.length;
    
    def decode_value_from(self, buf, offset, length):
        return bytes(buf[offset:offset+length])
    
    def encode_value_to(self, val, buf, offset, length):
        buf[offset:offset+length] = val


class IpAddressType(BytesType):
    """docstring for IpfixType"""
    def __init__(self, name, num, length):
        super().__init__(name, num, length)
    
    def decode_value_from(self, buf, offset, length):
        if length != self.length():
            raise ValueError("no RLE for addresses")
        return ip_address(bytes(buf[offset:offset+length]))
    
    def encode_value_to(self, val, buf, offset, length):
        if length != self.length():
            raise ValueError("no RLE for addresses")
        rsuper.encode_value_to(val.packed(), buf, offset, length)


class PackedType(IpfixType):
    """docstring for PackType"""
    def __init__(self, name, num, packstr, *rletypes):
        super().__init__(name, num)
        self.st = Struct(packstr)
        self.rletypes = rletypes
    
    def length(self):
        return self.st.size
    
    def decode_value_from(self, buf, offset, length):
        if length == self.length():
            return st.unpack_from(buf, offset)
        else:
            for rletype in self.rletypes:
                if length == rletype.length():
                    return rletype.decode_value_from(buf, offset, length)
            raise ValueError("no RLE for type " + self.name + " length " + length)
    
    def encode_value_to(self, val, buf, offset, length):
        if length == self.length():
            return st.pack_into(buf, offset, val);
        else:
            for rletype in self.rletypes:
                if length == rletype.length():
                    return rletype.encode_value_to(val, buf, offset, length)
            raise ValueError("no RLE for type " + self.name + " length " + length)

class BooleanType(PackedType):
    """docstring for BooleanType"""
    def __init__(self, name, num):
        super().__init__(name, num, "!B")
    
    def decode_value_from(self, buf, offset, length):
        return super().decode_value_from(self, buf, offset, length) == 1
    
    def encode_value_to(self, val, buf, offset, length):
        if val:
            smibool = 1
        else:
            smibool = 2
        super().encode_value_to(self, smibool, buf, offset, length)

class EpochSecondsType(PackedType):
    """docstring for EpochSecondsType"""
    def __init__(self, name, num):
        super().__init__(name, num, "!L")
    
    def decode_value_from(self, buf, offset, length):
        return datetime.utcfromtimestamp(super().decode_value_from(self, buf, offset, length))
    
    def encode_value_to(self, val, buf, offset, length):
        super().encode_value_to(self, val.timestamp(), buf, offset, length)


class EpochMillisecondsType(PackedType):
    """docstring for EpochMillisecondsType"""
    def __init__(self, name, num):
        super().__init__(name, num, "!Q")
    
    def decode_value_from(self, buf, offset, length):
        val = super().decode_value_from(self, buf, offset, length)
        return datetime.utcfromtimestamp(val/1000) + timedelta(milliseconds = val % 1000)
    
    def encode_value_to(self, val, buf, offset, length):
         super().encode_value_to(self, 
                 val.timestamp() * 1000 + val.microseconds / 1000, 
                 buf, offset, length)

# Builtin type registry

_Type_octetArray = BytesType("octetArray",  0, Varlen)
_Type_unsigned8  = PackedType("unsigned8",  0, "!B")
_Type_unsigned16 = PackedType("unsigned16", 0, "!H", _Type_unsigned8)
_Type_unsigned32 = PackedType("unsigned32", 0, "!L", _Type_unsigned16, _Type_unsigned8)
_Type_unsigned64 = PackedType("unsigned64", 0, "!Q", _Type_unsigned32, _Type_unsigned16, _Type_unsigned8)
_Type_signed8    = PackedType("signed8",    0, "!b")
_Type_signed16   = PackedType("signed16",   0, "!h", _Type_signed8)
_Type_signed32   = PackedType("signed32",   0, "!l", _Type_signed16, _Type_signed8)
_Type_signed64   = PackedType("signed64",   0, "!q", _Type_signed32, _Type_signed16, _Type_signed8)
_Type_float32    = PackedType("float32",    0, "!f")
_Type_float64    = PackedType("float64",    0, "!d", _Type_float32)
_Type_boolean    = BooleanType("boolean",   0)
_Type_dateTimeSeconds = EpochSecondsType("dateTimeSeconds", 0)
_Type_dateTimeMilliseconds = EpochMillisecondsType("dateTimeSeconds", 0)
_Type_dateTimeMicroseconds = IpfixType("dateTimeMicroseconds", 0)
_Type_dateTimeNanoseconds =  IpfixType("dateTimeNanoseconds", 0)
_Type_ipv4Address = IpAddressType("ipv4Address", 0, 4)
_Type_ipv6Address = IpAddressType("ipv6Address", 0, 16)
_Type_macAddress = BytesType("macAddress", 0, 6)
_Type_string     = IpfixType("string", 0)

_TypeForName = {'octetArray':           _Type_octetArray,
                'string':               _Type_string,
                'unsigned8':            _Type_unsigned8,
                'unsigned16':           _Type_unsigned16,
                'unsigned32':           _Type_unsigned32,
                'unsigned64':           _Type_unsigned64,
                'signed8':              _Type_signed8,
                'signed16':             _Type_signed16,
                'signed32':             _Type_signed32,
                'signed64':             _Type_signed64,
                'float32':              _Type_float32,
                'float64':              _Type_float64,
                'boolean':              _Type_boolean,
                'ipv4Address':          _Type_ipv4Address,
                'ipv6Address':          _Type_ipv6Address,
                'macAddress':           _Type_macAddress,
                'dateTimeSeconds':      _Type_dateTimeSeconds,
                'dateTimeMilliseconds': _Type_dateTimeMilliseconds,
                'dateTimeMicroseconds': _Type_dateTimeMicroseconds,
                'dateTimeNanoseconds':  _Type_dateTimeNanoseconds}

_ieForName = {}
_ieForNum = {}

def register_iana_ies():
    iespeclist = '''
octetDeltaCount(1)<unsigned64>[8]
packetDeltaCount(2)<unsigned64>[8]
protocolIdentifier(4)<unsigned8>[1]
ipClassOfService(5)<unsigned8>[1]
tcpControlBits(6)<unsigned8>[1]
sourceTransportPort(7)<unsigned16>[2]
sourceIPv4Address(8)<ipv4Address>[4]
sourceIPv4PrefixLength(9)<unsigned8>[1]
ingressInterface(10)<unsigned32>[4]
destinationTransportPort(11)<unsigned16>[2]
destinationIPv4Address(12)<ipv4Address>[4]
destinationIPv4PrefixLength(13)<unsigned8>[1]
egressInterface(14)<unsigned32>[4]
ipNextHopIPv4Address(15)<ipv4Address>[4]
bgpSourceAsNumber(16)<unsigned32>[4]
bgpDestinationAsNumber(17)<unsigned32>[4]
bgpNextHopIPv4Address(18)<ipv4Address>[4]
postMCastPacketDeltaCount(19)<unsigned64>[8]
postMCastOctetDeltaCount(20)<unsigned64>[8]
flowEndSysUpTime(21)<unsigned32>[4]
flowStartSysUpTime(22)<unsigned32>[4]
postOctetDeltaCount(23)<unsigned64>[8]
postPacketDeltaCount(24)<unsigned64>[8]
minimumIpTotalLength(25)<unsigned64>[8]
maximumIpTotalLength(26)<unsigned64>[8]
sourceIPv6Address(27)<ipv6Address>[16]
destinationIPv6Address(28)<ipv6Address>[16]
sourceIPv6PrefixLength(29)<unsigned8>[1]
destinationIPv6PrefixLength(30)<unsigned8>[1]
flowLabelIPv6(31)<unsigned32>[4]
icmpTypeCodeIPv4(32)<unsigned16>[2]
igmpType(33)<unsigned8>[1]
flowActiveTimeout(36)<unsigned16>[2]
flowIdleTimeout(37)<unsigned16>[2]
exportedOctetTotalCount(40)<unsigned64>[8]
exportedMessageTotalCount(41)<unsigned64>[8]
exportedFlowRecordTotalCount(42)<unsigned64>[8]
sourceIPv4Prefix(44)<ipv4Address>[4]
destinationIPv4Prefix(45)<ipv4Address>[4]
mplsTopLabelType(46)<unsigned8>[1]
mplsTopLabelIPv4Address(47)<ipv4Address>[4]
minimumTTL(52)<unsigned8>[1]
maximumTTL(53)<unsigned8>[1]
fragmentIdentification(54)<unsigned32>[4]
postIpClassOfService(55)<unsigned8>[1]
sourceMacAddress(56)<macAddress>[6]
postDestinationMacAddress(57)<macAddress>[6]
vlanId(58)<unsigned16>[2]
postVlanId(59)<unsigned16>[2]
ipVersion(60)<unsigned8>[1]
flowDirection(61)<unsigned8>[1]
ipNextHopIPv6Address(62)<ipv6Address>[16]
bgpNextHopIPv6Address(63)<ipv6Address>[16]
ipv6ExtensionHeaders(64)<unsigned32>[4]
mplsTopLabelStackSection(70)<octetArray>[3]
mplsLabelStackSection2(71)<octetArray>[3]
mplsLabelStackSection3(72)<octetArray>[3]
mplsLabelStackSection4(73)<octetArray>[3]
mplsLabelStackSection5(74)<octetArray>[3]
mplsLabelStackSection6(75)<octetArray>[3]
mplsLabelStackSection7(76)<octetArray>[3]
mplsLabelStackSection8(77)<octetArray>[3]
mplsLabelStackSection9(78)<octetArray>[3]
mplsLabelStackSection10(79)<octetArray>[3]
destinationMacAddress(80)<macAddress>[6]
postSourceMacAddress(81)<macAddress>[6]
interfaceName(82)<string>[65535]
interfaceDescription(83)<string>[65535]
octetTotalCount(85)<unsigned64>[8]
packetTotalCount(86)<unsigned64>[8]
fragmentOffset(88)<unsigned16>[2]
mplsVpnRouteDistinguisher(90)<octetArray>[8]
mplsTopLabelPrefixLength(91)<unsigned8>[1]
postIpDiffServCodePoint(98)<unsigned8>[1]
bgpNextAdjacentAsNumber(128)<unsigned32>[4]
bgpPrevAdjacentAsNumber(129)<unsigned32>[4]
exporterIPv4Address(130)<ipv4Address>[4]
exporterIPv6Address(131)<ipv6Address>[16]
droppedOctetDeltaCount(132)<unsigned64>[8]
droppedPacketDeltaCount(133)<unsigned64>[8]
droppedOctetTotalCount(134)<unsigned64>[8]
droppedPacketTotalCount(135)<unsigned64>[8]
flowEndReason(136)<unsigned8>[1]
commonPropertiesId(137)<unsigned64>[8]
observationPointId(138)<unsigned32>[4]
icmpTypeCodeIPv6(139)<unsigned16>[2]
mplsTopLabelIPv6Address(140)<ipv6Address>[16]
lineCardId(141)<unsigned32>[4]
portId(142)<unsigned32>[4]
meteringProcessId(143)<unsigned32>[4]
exportingProcessId(144)<unsigned32>[4]
templateId(145)<unsigned16>[2]
wlanChannelId(146)<unsigned8>[1]
wlanSSID(147)<string>[32]
flowId(148)<unsigned64>[8]
observationDomainId(149)<unsigned32>[4]
flowStartSeconds(150)<dateTimeSeconds>[4]
flowEndSeconds(151)<dateTimeSeconds>[4]
flowStartMilliseconds(152)<dateTimeMilliseconds>[8]
flowEndMilliseconds(153)<dateTimeMilliseconds>[8]
flowStartMicroseconds(154)<dateTimeMicroseconds>[8]
flowEndMicroseconds(155)<dateTimeMicroseconds>[8]
flowStartNanoseconds(156)<dateTimeNanoseconds>[8]
flowEndNanoseconds(157)<dateTimeNanoseconds>[8]
flowStartDeltaMicroseconds(158)<unsigned32>[4]
flowEndDeltaMicroseconds(159)<unsigned32>[4]
systemInitTimeMilliseconds(160)<dateTimeMilliseconds>[8]
flowDurationMilliseconds(161)<unsigned32>[4]
flowDurationMicroseconds(162)<unsigned32>[4]
observedFlowTotalCount(163)<unsigned64>[8]
ignoredPacketTotalCount(164)<unsigned64>[8]
ignoredOctetTotalCount(165)<unsigned64>[8]
notSentFlowTotalCount(166)<unsigned64>[8]
notSentPacketTotalCount(167)<unsigned64>[8]
notSentOctetTotalCount(168)<unsigned64>[8]
destinationIPv6Prefix(169)<ipv6Address>[16]
sourceIPv6Prefix(170)<ipv6Address>[16]
postOctetTotalCount(171)<unsigned64>[8]
postPacketTotalCount(172)<unsigned64>[8]
flowKeyIndicator(173)<unsigned64>[8]
postMCastPacketTotalCount(174)<unsigned64>[8]
postMCastOctetTotalCount(175)<unsigned64>[8]
icmpTypeIPv4(176)<unsigned8>[1]
icmpCodeIPv4(177)<unsigned8>[1]
icmpTypeIPv6(178)<unsigned8>[1]
icmpCodeIPv6(179)<unsigned8>[1]
udpSourcePort(180)<unsigned16>[2]
udpDestinationPort(181)<unsigned16>[2]
tcpSourcePort(182)<unsigned16>[2]
tcpDestinationPort(183)<unsigned16>[2]
tcpSequenceNumber(184)<unsigned32>[4]
tcpAcknowledgementNumber(185)<unsigned32>[4]
tcpWindowSize(186)<unsigned16>[2]
tcpUrgentPointer(187)<unsigned16>[2]
tcpHeaderLength(188)<unsigned8>[1]
ipHeaderLength(189)<unsigned8>[1]
totalLengthIPv4(190)<unsigned16>[2]
payloadLengthIPv6(191)<unsigned16>[2]
ipTTL(192)<unsigned8>[1]
nextHeaderIPv6(193)<unsigned8>[1]
mplsPayloadLength(194)<unsigned32>[4]
ipDiffServCodePoint(195)<unsigned8>[1]
ipPrecedence(196)<unsigned8>[1]
fragmentFlags(197)<unsigned8>[1]
octetDeltaSumOfSquares(198)<unsigned64>[8]
octetTotalSumOfSquares(199)<unsigned64>[8]
mplsTopLabelTTL(200)<unsigned8>[1]
mplsLabelStackLength(201)<unsigned32>[4]
mplsLabelStackDepth(202)<unsigned32>[4]
mplsTopLabelExp(203)<unsigned8>[1]
ipPayloadLength(204)<unsigned32>[4]
udpMessageLength(205)<unsigned16>[2]
isMulticast(206)<unsigned8>[1]
ipv4IHL(207)<unsigned8>[1]
ipv4Options(208)<unsigned32>[4]
tcpOptions(209)<unsigned64>[8]
paddingOctets(210)<octetArray>[1]
collectorIPv4Address(211)<ipv4Address>[4]
collectorIPv6Address(212)<ipv6Address>[16]
exportInterface(213)<unsigned32>[4]
exportProtocolVersion(214)<unsigned8>[1]
exportTransportProtocol(215)<unsigned8>[1]
collectorTransportPort(216)<unsigned16>[2]
exporterTransportPort(217)<unsigned16>[2]
tcpSynTotalCount(218)<unsigned64>[8]
tcpFinTotalCount(219)<unsigned64>[8]
tcpRstTotalCount(220)<unsigned64>[8]
tcpPshTotalCount(221)<unsigned64>[8]
tcpAckTotalCount(222)<unsigned64>[8]
tcpUrgTotalCount(223)<unsigned64>[8]
ipTotalLength(224)<unsigned64>[8]
postNATSourceIPv4Address(225)<ipv4Address>[4]
postNATDestinationIPv4Address(226)<ipv4Address>[4]
postNAPTSourceTransportPort(227)<unsigned16>[2]
postNAPTDestinationTransportPort(228)<unsigned16>[2]
natOriginatingAddressRealm(229)<unsigned8>[1]
natEvent(230)<unsigned8>[1]
initiatorOctets(231)<unsigned64>[8]
responderOctets(232)<unsigned64>[8]
firewallEvent(233)<unsigned8>[1]
ingressVRFID(234)<unsigned32>[4]
egressVRFID(235)<unsigned32>[4]
VRFname(236)<string>[65535]
postMplsTopLabelExp(237)<unsigned8>[1]
tcpWindowScale(238)<unsigned16>[2]
biflowDirection(239)<unsigned8>[1]
ethernetHeaderLength(240)<unsigned8>[1]
ethernetPayloadLength(241)<unsigned16>[2]
ethernetTotalLength(242)<unsigned16>[2]
dot1qVlanId(243)<unsigned16>[2]
dot1qPriority(244)<unsigned8>[1]
dot1qCustomerVlanId(245)<unsigned16>[2]
dot1qCustomerPriority(246)<unsigned8>[1]
metroEvcId(247)<string>[100]
metroEvcType(248)<unsigned8>[1]
pseudoWireId(249)<unsigned32>[4]
pseudoWireType(250)<unsigned16>[2]
pseudoWireControlWord(251)<unsigned32>[4]
ingressPhysicalInterface(252)<unsigned32>[4]
egressPhysicalInterface(253)<unsigned32>[4]
postDot1qVlanId(254)<unsigned16>[2]
postDot1qCustomerVlanId(255)<unsigned16>[2]
ethernetType(256)<unsigned16>[2]
postIpPrecedence(257)<unsigned8>[1]
selectionSequenceId(301)<unsigned64>[8]
selectorId(302)<unsigned16>[2]
informationElementId(303)<unsigned16>[2]
selectorAlgorithm(304)<unsigned16>[2]
samplingPacketInterval(305)<unsigned32>[4]
samplingPacketSpace(306)<unsigned32>[4]
samplingTimeInterval(307)<unsigned32>[4]
samplingTimeSpace(308)<unsigned32>[4]
samplingSize(309)<unsigned32>[4]
samplingPopulation(310)<unsigned32>[4]
samplingProbability(311)<float64>[8]
ipHeaderPacketSection(313)<octetArray>[65535]
ipPayloadPacketSection(314)<octetArray>[65535]
mplsLabelStackSection(316)<octetArray>[65535]
mplsPayloadPacketSection(317)<octetArray>[65535]
selectorIdTotalPktsObserved(318)<unsigned64>[8]
selectorIdTotalPktsSelected(319)<unsigned64>[8]
absoluteError(320)<float64>[8]
relativeError(321)<float64>[8]
observationTimeSeconds(322)<dateTimeSeconds>[4]
observationTimeMilliseconds(323)<dateTimeMilliseconds>[8]
observationTimeMicroseconds(324)<dateTimeMicroseconds>[8]
observationTimeNanoseconds(325)<dateTimeNanoseconds>[8]
digestHashValue(326)<unsigned64>[8]
hashIPPayloadOffset(327)<unsigned64>[8]
hashIPPayloadSize(328)<unsigned64>[8]
hashOutputRangeMin(329)<unsigned64>[8]
hashOutputRangeMax(330)<unsigned64>[8]
hashSelectedRangeMin(331)<unsigned64>[8]
hashSelectedRangeMax(332)<unsigned64>[8]
hashDigestOutput(333)<boolean>[1]
hashInitialiserValue(334)<unsigned64>[8]
selectorName(335)<string>[65535]
upperCILimit(336)<float64>[8]
lowerCILimit(337)<float64>[8]
confidenceLevel(338)<float64>[8]
informationElementDataType(339)<unsigned8>[1]
informationElementDescription(340)<string>[65535]
informationElementName(341)<string>[65535]
informationElementRangeBegin(342)<unsigned64>[8]
informationElementRangeEnd(343)<unsigned64>[8]
informationElementSemantics(344)<unsigned8>[1]
informationElementUnits(345)<unsigned16>[2]
privateEnterpriseNumber(346)<unsigned32>[4]
'''.splitlines()

    for iespec in iespeclist:
        if len(iespec):
            try:
                InformationElement.for_spec(iespec)
            except ValueError:
                print("error registering iespec "+iespec)

def _register_ie(ie):
    _ieForName[ie.name] = ie
    _ieForNum[(ie.pen, ie.num)] = ie
    
    return ie
    
@total_ordering
class InformationElement:
    """Represents a typed IPFIX Information Element"""
    def __init__(self, name, pen, num, ietype, length):
        
        if name:
            self.name = name
        else: 
            self.name = "_ipfix_%u_%u" % (pen, num)

        self.pen = pen
        self.num = num
        self.type = ietype
        
        if length:
            self.length = length
        else:
            self.length = self.type.length()
        
    
    def __eq__(self, other):
        return ((self.pen, self.num) == (other.pen, other.num))
    
    def __lt__(self, other):
        return ((self.pen, self.num) < (other.pen, other.num))

    def __repr__(self):
        return "InformationElement(%s, %s, %s, %s, %s)" % (repr(self.name), 
               repr(self.pen), repr(self.num), repr(self.type), 
               repr(self.length))

    def __str__(self):
        return "%s(%u/%u)%s[%u]" % (self.name, self.pen, self.num, str(self.type), self.length)
    
    def for_length(self, length):
        if not length or length == self.length:
            return self
        else:
            return self.__class__(self.name, self.pen, self.num, self.type, length)

    @classmethod
    def for_spec(cls, spec):
        (name, pen, num, typename, length) = _iespec_re.match(spec).group(1,4,5,7,9)

        if not name and not pen and not num and not typename and not length:
            raise ValueError("unrecognized IE spec "+spec)
        
        if pen: 
            pen = int(pen)
        else:
            pen = 0
        
        if num:
            num = int(num)
        else:
            num = 0
        
        if length:
            length = int(length)
        else:
            length = 0
        
        if name and not pen and not num and name in _ieForName:
                # lookup in name registry
                return _ieForName[name].for_length(length)
        
        if num and (pen, num) in _ieForNum:
                # lookup in number registry
                return _ieForNum[(pen, num)].for_length(length)
        
        # try to create new registered IE
        if not typename:
            raise ValueError("Cannot create new IE without valid type")
        
        if typename not in _TypeForName:
            raise ValueError("unrecognized type name "+typename)
        
        ietype = _TypeForName[typename]
        return _register_ie(cls(name, pen, num, ietype, length))
     
    @classmethod
    def for_template_entry(cls, pen, num, length):
        if ((pen, num) in _ieForNum):
            return _ieForNum[(pen, num)].for_length(length)
        
        return _register_ie(cls(None, pen, num, _TypeForName["octetArray"], length))
    

class Template:
    """Represents an ordered list of IPFIX Information Elements with an ID"""
    def __init__(self, tid = 0):
        super(Template, self).__init__()
        self.ies = [];
        self.tid = tid;

    def __iter__(self):
        return ies.__iter__()

    def append(self, ie):
        self.ies.append(ie)
    
    # FIXME all record encode/decode stuff lives in template
    # we probably want a callback-based interface too
    
    def decode_dict_from(self, buf, offset):
        rec = {}
        for ie in ies:
            if (ie.length == Varlen):
                raise ValueError("no varlen support yet")
            else:
                length = ie.length
                
            rec[ie.name] = ie.type.decode_value_from(buf, offset, length)
            offset += length
        
        return (rec, offset)

    def encode_dict_to(self, rec, buf, offset):
        for ie in ies:
            if (ie.length == Varlen):
                raise ValueError("no varlen support yet")
            else:
                length = ie.length
            
            val = rec[ie.name]
            ie.type.encode_value_to(val, buf, offset, length)
            offset += length
            
        return offset
    
    @classmethod
    def decode_template_from(cls, buf, offset):
        (tid, count) = _tmplhdr_st.unpack_from(buf, offset);
        tmpl = cls(tid)
        offset += _tmplhdr_st.calclength()
        while count:
            (num, length) = _iespec_st.unpack_from(buf, offset)
            offset += _iespec_st.calclength()
            if num & 0x8000:
                num &= 0x7fff
                (pen) = _iepen_st.unpack_from(buf, offset)
                offset += _iespec_st.calclength()
            else:
                pen = 0
            tmpl.append(InformationElement.for_template_entry(pen, num, length))
            count -= 1

    def encode_template_to(self, buf, offset):
        _tmplhdr_st.pack_into(buf, offset, self.tid, len(self.ies))
        for ie in ies:
            if ie.pen:
                _iespec_st.pack_into(buf, offset, ie.num | 0x8000, ie.length)
                offset += _iespec_st.calclength()
                _iepen_st.pack_into(buf, offset, ie.pen)
                offset += _iepen_st.calclength()
            else: 
                _iespec_st.pack_into(buf, offset, ie.num, ie.length)
                offset += _iespec_st.calclength()

class MessageStreamReader:
    """docstring for MessageStreamReader"""
    def __init__(self, stream):
        self.stream = stream
        self.mbuf = bytearray(65536)
        self.length = 0
        self.sequence = None
        self.export_time = None
        self.domain_id = None
        self.setlist = []
        self.templates = {}
    
    """deframe message and find set offsets"""
    def deframe(self):
        # Start at the beginning
        offset = 0
        self.setlist.clear()
        
        # deframe and parse message header 
        self.mbuf[0:_msghdr_st.size] = self.stream.read(_msghdr_st.size)
        (version, self.length, self.sequence, self.export_time, self.domain_id) = _msghdr_st.unpack_from(self.mbuf, offset)
        offset += _msghdr_st.size
        
        # verify version and length
        if version != 10:
            raise IPFIXDecodeError("Illegal or unsupported version " + str(version))
        
        if self.length < 20:
            raise IPFIXDecodeError("Illegal message length" + str(self.length))
            
        # read the rest of the message into the buffer
        self.mbuf[offset:length-offset] = self.stream.read(length-offset)
        
        # iterate over message and built setlist
        while (offset < self.length):
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, offset)
            if offset + setlen > self.length:
                raise IPFIXDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen

    def dict_iterator(self):
        
        try:
            while(True):
                self.deframe()
                for (offset, setid, setlen) in setlist:
                    if setid == 2:
                        pass
                    elif setid == 3:
                        pass
                    elif setid < 256:
                        # FIXME warn on this instead
                        raise IPFIXDecodeError("illegal set ID")
                    else:
                        pass
        except EOFError:
            return
                    
                    