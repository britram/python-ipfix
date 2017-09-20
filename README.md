python-ipfix
============

IPFIX implementation for Python 3.3.

This module provides a Python interface to IPFIX message streams, and
provides tools for building IPFIX Exporting and Collecting Processes.
It handles message framing and deframing, encoding and decoding IPFIX
data records using templates, and a bridge between IPFIX ADTs and
appropriate Python data types.

It should work on Python 2.7 as well; your mileage may vary. To install on
Python 2.7, the following additional dependencies must be manually installed:

- pip install functools32
- pip install py2-ipaddress
- pip install pytz
