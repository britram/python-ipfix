import doctest

import ipfix.types
import ipfix.ie
import ipfix.message

doctest.testmod(ipfix.types)
doctest.testmod(ipfix.ie)
doctest.testmod(ipfix.message)