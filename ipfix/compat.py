try:
    # Python 3 imports
    from datetime import timezone
    import urllib.request as urlreq
    from functools import lru_cache

    # These will succeed in Python 2, but we won't get here due to
    # ImportError from the previous lines.
    izip = zip
    xrange = range
    ifilter = filter
    from functools import reduce
except ImportError:
    import pytz as timezone
    import urllib2 as urlreq
    from functools32 import lru_cache

    from itertools import izip, ifilter
    xrange = xrange
    reduce = reduce

def _get_memoryview_buffer(bufsize):
    return memoryview(bytearray(bufsize))


def _get_fake_memoryview_buffer(bufsize):
    return _FakeMemoryView(bufsize)


class _FakeMemoryView(bytearray):
    """
    Python 2.7.8 has a bug that prevents struct.pack_into from
    working with a memoryview: http://bugs.python.org/issue22113

    This class just acts like a memoryview from the perspective
    of the rest of the library (though it lacks the performance benefits).
    It can and should go away if this bug gets fixed in a later 2.7 version.
    """

    def __getitem__(self, key):
        _slice = bytearray.__getitem__(self, key)
        return _FakeMemoryView(_slice)

    def tobytes(self):
        return self

    def tolist(self):
        return list(self)

try:
    length = 10
    mv = memoryview(bytearray(length))
    mv[0:length] = bytearray([0] * length)
    import struct
    struct.pack_into("!HLL", mv, 0, 42, 17, 21)

    # if slice assignment succeeded, no bug.
    get_buffer = _get_memoryview_buffer
except TypeError:
    # slice assignment bug exists.
    # return a bytearray with the few extra methods that
    # the MessageBuffer wants. Less efficient, but not broken.
    get_buffer = _get_fake_memoryview_buffer


def _datetime_to_timestamp_by_duration(datetime_):
    # from python3 docs
    dur = (datetime_ - datetime.datetime(1970, 1, 1, tzinfo=timezone.utc))
    return dur.total_seconds()

import datetime
if hasattr(datetime.datetime, 'timestamp'):
    datetime_to_timestamp = getattr(datetime.datetime, 'timestamp')
else:
    datetime_to_timestamp = _datetime_to_timestamp_by_duration
