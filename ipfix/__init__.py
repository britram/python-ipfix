"""
IPFIX implementation for Python 3.x.

This module provides a Python interface to IPFIX message streams, and
provides tools for building IPFIX Exporting and Collecting Processes.
It handles message framing and deframing, encoding and decoding IPFIX
data records using templates, and a bridge between IPFIX ADTs and
appopriate Python data types.

The following modules provide specific services:

ipfix.reader -- iterator over records read from IPFIX messages on a stream.
ipfix.writer -- interface to write records to IPFIX messages on
                a stream, with automatic message boundary management
ipfix.message -- provides the MessageBuffer class for direct control over
                 IPFIX message reading and writing
ipfix.template -- template-based packing and unpacking of data from
                  IPFIX messages, used internally by ipfix.message.
ipfix.ie -- iespec-based interface to IPFIX information elements,
            and interface to use the default IPFIX IANA Information Model
ipfix.type -- encoding and decoding of data items to appropriate Python types
ipfix.ieutils -- Utilities for updating the module's information model
                 from IANA
"""