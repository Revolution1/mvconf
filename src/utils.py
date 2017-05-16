import functools
from inspect import getargspec
from itertools import chain
from types import StringType
from types import StringTypes

from ipaddress import IPv4Address


def memoize(fn):
    cache = fn.cache = {}

    @functools.wraps(fn)
    def _memoize(*args, **kwargs):
        kwargs.update(dict(zip(getargspec(fn).args, args)))
        key = tuple(kwargs.get(k, None) for k in getargspec(fn).args)
        if key not in cache:
            cache[key] = fn(**kwargs)
        return cache[key]

    return _memoize


def _u(s):
    return unicode(s) if isinstance(s, StringType) else s


def ip_range_iter(start, end):
    temp = _start = IPv4Address(_u(start))
    _end = IPv4Address(_u(end))
    if not _start <= _end:
        raise ValueError("Start address '%s' must be smaller than end address '%s'" % (start, end))
    while temp <= _end:
        yield temp
        temp = temp + 1


def ip_pool_iter(conf):
    if isinstance(conf, StringTypes):
        split = _u(conf).split('-')
        if len(split) == 1:
            return split
        elif len(split) == 2:
            return ip_range_iter(*split)
        else:
            raise ValueError("Unknown ip-pool conf: '%s'" % conf)
    elif isinstance(conf, (list, tuple)):
        return chain(*[ip_pool_iter(c) for c in conf])
    else:
        raise ValueError("ip pool configuration must be string or list/tuple")


if __name__ == '__main__':
    print list(ip_pool_iter([
        "192.168.8.136",
        "192.168.8.137-192.168.8.139",
        "192.168.8.140-192.168.8.155"
    ]))
