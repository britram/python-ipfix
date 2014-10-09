python-ipfix
============

IPFIX implementation for Python 3.3.

This module provides a Python interface to IPFIX message streams, and
provides tools for building IPFIX Exporting and Collecting Processes.
It handles message framing and deframing, encoding and decoding IPFIX
data records using templates, and a bridge between IPFIX ADTs and
appopriate Python data types.


WIP: porting to Python 2.7.
New dependencies:
    pip install functools32
    pip install py2-ipaddress
    pip install pytz

New test dependencies:
    pip install doctest-ignore-unicode
