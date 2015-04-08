# Copyright 2003-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: DNSFarm.py,v 1.11 2004/03/07 06:31:46 nickm Exp $

"""mixminion.server.DNSFarm: code to implement asynchronous DNS resolves
   asynchronously and cachhe the results.
   """

import time
import sys
import select
import mixminion.NetUtils
from mixminion.Common import LOG

__all__ = [ 'DNSCache' ]

class _Pending:
    """Class to represent resolves that we're waiting for an answer on."""
    def __cmp__(self,o):
        return cmp(type(self), type(o))
PENDING = _Pending()

# We clear entries from the DNS cache when they're more than MAX_ENTRY_TTL
# seconds old...
MAX_ENTRY_TTL = 30*60
# ...and entries from the reverse cache after MAX_RENTRY_TTL seconds.
MAX_RENTRY_TTL = 24*60*60

class DNSCache:
    """Class to cache answers to DNS requests asynchronously"""
    ## Fields:
    # cache: map from name to PENDING or getIP result.
    # rCache: map from (family,lowercase IP) to (hostname, time).
    # callbacks: map from name to list of callback functions. (See lookup
    #     for definition of callback.)
    def __init__(self, default_async=True):
        """Create a new DNSCache"""
        self.cache = {}
        self.rCache = {}
        self.callbacks = {}
        self.async_requests = []
        self.sync_requests = []
        self.cleanCache()
        self.default_async = default_async

    def getNonblocking(self, name):
        """Return the cached result for the lookup of name.  If we're
           waiting for an answer, return PENDING.  If there is no cached
           result, return None.
        """
        return self.cache.get(name)

    def getNameByAddressNonblocking(self, addr, family=None):
        """Given an IP address (and optionally a family), if we have gotten
           the address as a result in the past, return the hostname that
           most recently resolved to the address, or None if no such hostname
           is found."""
        if family is None:
            if ':' in addr:
                family = mixminion.NetUtils.AF_INET6
            else:
                family = mixminion.NetUtils.AF_INET
        v = self.rCache.get((family,addr.lower()))
        if v is None:
            return None
        else:
            return v[0]

    def lookup(self,name,cb, async=None):
        """Look up the name 'name', and pass the result to the callback
           function 'cb' when we're done.  The result will be of the
           same form as the return value of NetUtils.getIP: either
           (Family, Address, Time) or ('NOENT', Reason, Time).
        """
        if async is None:
            async = self.default_async
        # Check for a static IP first; no need to resolve that.
        v = mixminion.NetUtils.nameIsStaticIP(name)
        if v is not None:
            cb(name,v)
            return

        v = self.cache.get(name)
        # If we don't have a cached answer, add cb to self.callbacks
        if v is None or v is PENDING:
            self.callbacks.setdefault(name, []).append(cb)
        # If we aren't looking up the answer, start looking it up.
        if v is None:
            LOG.trace("DNS cache starting lookup of %r", name)
            self._beginLookup(name, async)
        # If we _did_ have an answer, invoke the callback now.
        if v is not None and v is not PENDING:
            LOG.trace("DNS cache returning cached value %s for %r",
                      v,name)
            cb(name,v)

    def process(self):
        new_pending = []
        for name, request in self.async_requests:
            ret = mixminion.NetUtils.gai_error(request)
            if ret == mixminion.NetUtils.EAI_INPROGRESS:
                new_pending.append((name, request))
            elif ret != 0:
                msg = mixminion.NetUtils.gai_strerror(ret)
                raise Exception("Lookup failed: %s" % msg)
            else:
                results = []
                addrinfo = request.contents.ar_result
                addrs = mixminion.NetUtils.get_addrs_from_addrinfo(addrinfo)
                final_result = mixminion.NetUtils.filter_IPs(addrs, name)
                self._lookupDone(name, final_result)
        self.async_requests = new_pending
        while self.sync_requests:
            name, result = self.sync_requests.pop()
            self._lookupDone(name, result)

    def shutdown(self, wait=0):
        """Cancel all pending requests"""
        for req in self.async_requests:
            mixminion.NetUtils.gai_cancel(req)

    def cleanCache(self,now=None):
        """Remove all expired entries from the cache."""
        if now is None:
            now = time.time()

        # Purge old entries from the caches.
        cache = self.cache
        for name in cache.keys():
            v = cache[name]
            if v is PENDING: continue
            if now-v[2] > MAX_ENTRY_TTL:
                del cache[name]
        rCache = self.rCache
        for name in rCache.keys():
            v=rCache[name]
            if now-v[1] > MAX_RENTRY_TTL:
                del rCache[name]

    def _beginLookup(self,name, async):
        """Helper function: Begin looking up 'name'.

           Caller must hold self.lock
        """
        self.cache[name] = PENDING
        if async:
            request = mixminion.NetUtils.getIP_async(name)
            self.async_requests.append((name, request))
        else:
            result = mixminion.NetUtils.getIP(name)
            self.sync_requests.append((name, result))

    def _lookupDone(self,name,val):
        """Helper function: invoked when we get the answer 'val' for
           a lookup of 'name'.
           """
        # Insert the value in the cache.
        self.cache[name]=val
        # Insert the value in the reverse cache.
        if val[0] != 'NOENT':
            self.rCache[(val[0], val[1].lower())] = (name.lower(),val[2])
        # Get the callbacks for the name, if any.
        cbs = self.callbacks.get(name,[])
        try:
            del self.callbacks[name]
        except KeyError:
            pass
        # Now that we've released the lock, invoke the callbacks.
        for cb in cbs:
            cb(name,val)
