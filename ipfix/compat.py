def _get_memoryview_buffer(bufsize):
    return memoryview(bytearray(bufsize))


def _get_fake_memoryview_buffer(bufsize):
    return _FakeMemoryView(bufsize)


class _FakeMemoryView(bytearray):
    """
    Python 2.7.8 has a bug wherein a slice assignment to a memoryview
    that wraps a bytearray causes a "cannot "
    """

    def __getitem__(self, key):
        _slice = bytearray.__getitem__(self, key)
        return _FakeMemoryView(_slice)

    def tobytes(self):
        return self

    def tolist(self):
        return list(self)

try:
    mv = memoryview(bytearray(10))
    mv[1:4] = str([42] * 10)

    # if slice assignment succeeded, no bug.
    get_buffer = _get_memoryview_buffer
except ValueError:
    # slice assignment bug exists.
    # return a bytearray with the few extra methods that
    # the MessageBuffer wants. Less efficient, but not broken.
    get_buffer = _get_fake_memoryview_buffer


def _datetime_to_timestamp_by_duration(datetime_):
    # from python3 docs
    import pytz as timezone
    dur = (datetime_ - datetime.datetime(1970, 1, 1, tzinfo=timezone.utc))
    return dur.total_seconds()

import datetime
if hasattr(datetime.datetime, 'timestamp'):
    datetime_to_timestamp = getattr(datetime.datetime, 'timestamp')
else:
    datetime_to_timestamp = _datetime_to_timestamp_by_duration
