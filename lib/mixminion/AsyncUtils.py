import errno
import socket
import select
import re
import sys
import threading
import time
from types import StringType

import mixminion.ServerInfo
import mixminion.TLSConnection
import mixminion._minionlib as _ml
from mixminion.Common import MixError, MixFatalError, MixProtocolError, \
     LOG, stringContains, floorDiv, UIError
from mixminion.Crypto import sha1, getCommonPRNG
from mixminion.Packet import PACKET_LEN, DIGEST_LEN, IPV4Info, MMTPHostInfo
from mixminion.NetUtils import getProtocolSupport, AF_INET, AF_INET6
import mixminion.server.EventStats as EventStats
from mixminion.Filestore import CorruptedFile
from mixminion.ThreadUtils import MessageQueue, QueueEmpty


class SelectAsyncServer:
    """AsyncServer is the core of a general-purpose asynchronous
       select-based server loop.  AsyncServer maintains lists of
       Connection objects that are waiting for reads and writes
       (respectively), and waits for their underlying sockets to be
       available for the desired operations.
       """
    ## Fields:
    # self.connections: a map from fd to Connection objects.
    # self.state: a map from fd to the latest wantRead,wantWrite tuples
    #    returned by the connection objects' process or getStatus methods.

    # self.bandwidthPerTick: How many bytes of bandwidth do we use per tick,
    #    on average?
    # self.maxBucket: How many bytes of bandwidth are we willing to use in
    #    a single 1-tick burst?
    # self.bucket: How many bytes are we willing to use in the next tick?
    #
    #   (NOTE: if no bandwidth limitation is used, the 3 fields above are
    #   set to None.)

    # How many seconds pass between the 'ticks' at which we increment
    # our bandwidth bucket?
    TICK_INTERVAL = 1.0

    def __init__(self):
        """Create a new AsyncServer with no readers or writers."""
        self._timeout = None
        self.connections = {}
        self.state = {}
        self.bandwidthPerTick = self.bucket = self.maxBucket = None

    def process(self,timeout):
        """If any relevant file descriptors become available within
           'timeout' seconds, call the appropriate methods on their
           connections and return immediately after. Otherwise, wait
           'timeout' seconds and return.

           If we receive an unblocked signal, return immediately.
           """
        readfds = []; writefds = []; exfds = []
        for fd,(wr,ww) in self.state.items():
            if wr: readfds.append(fd)
            if ww==2: exfds.append(fd)
            if ww: writefds.append(fd)

        if not (readfds or writefds or exfds):
            # Windows 'select' doesn't timeout properly when we aren't
            # selecting on any FDs.  This should never happen to us,
            # but we'll check for it anyway.
            time.sleep(timeout)
            return

        if self.bucket is not None and self.bucket <= 0:
            time.sleep(timeout)
            return

        try:
            readfds,writefds,exfds = select.select(readfds,writefds,exfds,
                                                   timeout)
        except select.error, e:
            if e[0] == errno.EINTR:
                return
            else:
                raise e

        writefds += exfds

        active = []

        for fd, c in self.connections.items():
            r = fd in readfds
            w = fd in writefds
            if not (r or w):
                continue
            active.append((c,r,w,fd))

        if not active: return
        if self.bucket is None:
            cap = None
        else:
            cap = floorDiv(self.bucket, len(active))
        for c,r,w,fd in active:
            wr, ww, isopen, nbytes = c.process(r,w,0,cap)
            if cap is not None:
                self.bucket -= nbytes
            if not isopen:
                del self.connections[fd]
                del self.state[fd]
                continue
            self.state[fd] = (wr,ww)

    def register(self, c):
        """Add a connection to this server."""
        fd = c.fileno()
        wr, ww, isopen = c.getStatus()
        if not isopen: return
        self.connections[fd] = c
        self.state[fd] = (wr,ww)

    def remove(self, c, fd=None):
        """Remove a connection from this server."""
        if fd is None:
            fd = c.fileno()
        del self.connections[fd]
        del self.state[fd]

    def tryTimeout(self, now=None):
        """Timeout any connection that is too old."""
        if self._timeout is None:
            return
        if now is None:
            now = time.time()
        # All connections older than 'cutoff' get purged.
        cutoff = now - self._timeout
        # Maintain a set of filenos for connections we've checked, so we don't
        # check any more than once.
        for fd, con in self.connections.items():
            if con.tryTimeout(cutoff):
                self.remove(con,fd)

    def setBandwidth(self, n, maxBucket=None):
        """Set bandwidth limitations for this server
              n -- maximum bytes-per-second to use, on average.
              maxBucket -- maximum bytes to send in a single burst.
                 Defaults to n*5.

           Setting n to None removes bandwidth limiting."""
        if n is None:
            self.bandwidthPerTick = None
            self.maxBucket = None
        else:
            self.bandwidthPerTick = int(n * self.TICK_INTERVAL)
            if maxBucket is None:
                self.maxBucket = self.bandwidthPerTick*5
            else:
                self.maxBucket = maxBucket

    def tick(self):
        """Tell the server that one unit of time has passed, and the bandwidth
           limitations can be readjusted.  This method must be called once
           every TICK_INTERVAL seconds."""
        bwpt = self.bandwidthPerTick
        if bwpt is None:
            self.bucket = None
        else:
            bucket = (self.bucket or 0) + bwpt
            if bucket > self.maxBucket:
                self.bucket = self.maxBucket
            else:
                self.bucket = bucket

class PollAsyncServer(SelectAsyncServer):
    """Subclass of SelectAsyncServer that uses 'poll' where available.  This
       is more efficient, but less universal."""
    def __init__(self):
        SelectAsyncServer.__init__(self)
        self.poll = select.poll()
        self.EVENT_MASK = {(0,0):0,
                           (1,0): select.POLLIN+select.POLLERR,
                           (0,1): select.POLLOUT+select.POLLERR,
                           (0,2): select.POLLOUT+select.POLLERR,
                           (1,1): select.POLLIN+select.POLLOUT+select.POLLERR,
                           (1,2): select.POLLIN+select.POLLOUT+select.POLLERR }
    def process(self,timeout):
        if self.bucket is not None and self.bucket <= 0:
            time.sleep(timeout)
            return
        try:
            # (watch out: poll takes a timeout in msec, but select takes a
            #  timeout in sec.)
            events = self.poll.poll(timeout*1000)
        except select.error, e:
            if e[0] == errno.EINTR:
                return
            else:
                raise e
        if not events:
            return
        if self.bucket is None:
            cap = None
        else:
            cap = floorDiv(self.bucket,len(events))
        #print events, self.connections.keys()
        for fd, mask in events:
            c = self.connections[fd]
            wr,ww,isopen,n = c.process(mask&select.POLLIN, mask&select.POLLOUT,
                                       mask&(select.POLLERR|select.POLLHUP),
                                       cap)
            if cap is not None:
                self.bucket -= n
            if not isopen:
                #print "unregister",fd
                self.poll.unregister(fd)
                del self.connections[fd]
                continue
            #print "register",fd
            self.poll.register(fd,self.EVENT_MASK[wr,ww])

    def register(self,c):
        fd = c.fileno()
        wr, ww, isopen = c.getStatus()
        if not isopen: return
        self.connections[fd] = c
        mask = self.EVENT_MASK[(wr,ww)]
        #print "register",fd
        self.poll.register(fd, mask)
    def remove(self,c,fd=None):
        if fd is None:
            fd = c.fileno()
        #print "unregister",fd
        self.poll.unregister(fd)
        del self.connections[fd]


class EPollAsyncServer(SelectAsyncServer):
    """Subclass of SelectAsyncServer that uses 'poll' where available.  This
       is more efficient, but less universal."""

    def __init__(self):
        SelectAsyncServer.__init__(self)
        self.epoll = select.epoll()
        self.EVENT_MASK = {
            (0, 0): 0,
            (1, 0): select.EPOLLIN + select.EPOLLERR,
            (0, 1): select.EPOLLOUT + select.EPOLLERR,
            (0, 2): select.EPOLLOUT + select.EPOLLERR,
            (1, 1): select.EPOLLIN + select.EPOLLOUT + select.EPOLLERR,
            (1, 2): select.EPOLLIN + select.EPOLLOUT + select.EPOLLERR,
        }

    def process(self, timeout):
        try:
            events = self.epoll.poll(timeout)
        except IOError as e:
            if e[0] == errno.EINTR:
                return
            else:
                raise e

        if not events:
            return

        if self.bucket is None:
            cap = None
        else:
            cap = floorDiv(self.bucket, len(events))

        for fd, mask in events:
            c = self.connections[fd]
            wr, ww, isopen, n = c.process(
                mask & select.EPOLLIN,
                mask & select.EPOLLOUT,
                mask & (select.EPOLLERR | select.EPOLLHUP),
                cap)
            if cap is not None:
                self.bucket -= n
            if not isopen:
                self.remove(c, fd)
                continue
            self.epoll.modify(fd,self.EVENT_MASK[wr,ww])

    def register(self, c):
        fd = c.fileno()
        wr, ww, isopen = c.getStatus()
        if not isopen:
            return
        self.connections[fd] = c
        mask = self.EVENT_MASK[(wr, ww)]
        self.epoll.register(fd, mask)

    def remove(self, c, fd=None):
        if fd is None:
            fd = c.fileno()
        self.epoll.unregister(fd)
        del self.connections[fd]


if hasattr(select,'poll') and not _ml.POLL_IS_EMULATED and sys.platform != 'cygwin':
    # Prefer 'poll' to 'select', except on MacOS and other platforms where
    # where 'poll' is just a wrapper around 'select'.  (The poll wrapper is
    # sometimes buggy.)
    if hasattr(select, 'epoll'):
        AsyncServer = EPollAsyncServer
    else:
        AsyncServer = PollAsyncServer
else:
    AsyncServer = SelectAsyncServer
