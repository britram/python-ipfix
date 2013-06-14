"""
IPFIX implementation for Python 3.x.

.. moduleauthor:: Brian Trammell <brian@trammell.ch>

This module provides a Python interface to IPFIX message streams, and
provides tools for building IPFIX Exporting and Collecting Processes.
It handles message framing and deframing, encoding and decoding IPFIX
data records using templates, and a bridge between IPFIX ADTs and
appopriate Python data types.

"""