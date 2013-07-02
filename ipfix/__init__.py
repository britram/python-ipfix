#
# python-ipfix (c) 2013 Brian Trammell.
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

This module is copyright 2013 Brian Trammell. It is made available under the
terms of the 
`GNU Lesser General Public License <http://www.gnu.org/licenses/lgpl.html>`_, 
or, at your option, any later version.

"""

from . import types
from . import ie
from . import template
from . import message
