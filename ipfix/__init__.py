"""
IPFIX implementation for Python 3.3.

.. moduleauthor:: Brian Trammell <brian@trammell.ch>

This module provides a Python interface to IPFIX message streams, and
provides tools for building IPFIX Exporting and Collecting Processes.
It handles message framing and deframing, encoding and decoding IPFIX
data records using templates, and a bridge between IPFIX ADTs and
appropriate Python data types.

Before using any of the functions of this module, it is necessary to populate
the information model with Information Elements.
:func:`ipfix.ie.use_iana_default` populates the default IANA IPFIX Information
Element Registry shipped with the module; this is the current registry as of
release time. :func:`ipfix.ie.use_5103_default` populates the reverse
counterpart IEs as in :rfc:`5103`. The module also supports the definition of 
enterprise-specific Information Elements via :func:`ipfix.ie.for_spec()` and 
:func:`ipfix.ie.use_specfile()`; see :mod:`ipfix.ie` for more.

For reading and writing of records to IPFIX message streams with automatic
message boundary management, see the :mod:`ipfix.reader` and
:mod:`ipfix.writer` modules, respectively. For manual reading and writing of
messages, see :mod:`ipfix.message`. In any case, exporters will need to define
templates; see :mod:`ipfix.template`.

"""

from . import types
from . import ie
from . import template
from . import message
