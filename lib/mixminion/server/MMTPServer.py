# Copyright 2002-2004 Nick Mathewson.  See LICENSE for licensing information.
# $Id: MMTPServer.py,v 1.84 2004/03/23 00:09:24 nickm Exp $
"""mixminion.MMTPServer

   This package implements the Mixminion Transfer Protocol as described
   in the Mixminion specification.  It uses a select loop to provide
   a nonblocking implementation of *both* the client and the server sides
   of the protocol.

   If you just want to send packets into the system, use MMTPClient.
   """

# NOTE FOR THE CURIOUS: The 'asyncore' module in the standard library
#    is another general select/poll wrapper... so why are we using our
#    own?  Basically, because asyncore has IMO a couple of mismatches
#    with our design, the largest of which is that it has the 'server
#    loop' periodically query the connections for their status,
#    whereas we have the connections inform the server of their status
#    whenever they change.  This latter approach turns out to be far
#    easier to use with TLS.

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
from mixminion.MMTPClient import PeerCertificateCache, MMTPClientConnection
from mixminion.NetUtils import getProtocolSupport, AF_INET, AF_INET6
import mixminion.server.EventStats as EventStats
from mixminion.Filestore import CorruptedFile
from mixminion.ThreadUtils import MessageQueue, QueueEmpty
from mixminion.AsyncUtils import AsyncServer

__all__ = [ 'AsyncServer', 'ListenConnection', 'MMTPServerConnection',
            'MMTPClientConnection' ]

class Connection:
    "A connection is an abstract superclass for asynchronous channels"
    def process(self, r, w, x, cap):
        """Invoked when there is data to read or write.  Must return a 4-tuple
           of (wantRead, wantWrite, isOpen, bytesUsed)."""
        return 0,0,0,0
    def getStatus(self):
        """Returns the same 3-tuple as process, without bytesUsed."""
        return 0,0,0
    def fileno(self):
        """Returns an integer file descriptor for this connection, or returns
           an object that can return such a descriptor."""
        pass
    def tryTimeout(self, cutoff):
        """If this connection has seen no activity since 'cutoff', and it
           is subject to aging, shut it down."""
        pass

class ListenConnection(Connection):
    """A ListenConnection listens on a given port/ip combination, and calls
       a 'connectionFactory' method whenever a new connection is made to that
       port."""
    ## Fields:
    # ip: IP to listen on.
    # port: port to listen on.
    # sock: socket to bind.
    # connectionFactory: a function that takes as input a socket from a
    #    newly received connection, and returns a Connection object to
    #    register with the async server.
    def __init__(self, family, ip, port, backlog, connectionFactory):
        """Create a new ListenConnection"""
        self.ip = ip
        self.port = port
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setblocking(0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.ip, self.port))
        except socket.error, (err,msg):
            extra = ""
            code = errno.errorcode.get(err)
            if code in ["EADDRNOTAVAIL", "WSAEADDRNOTAVAIL"]:
                extra = " (Is that really your IP address?)"
            elif code == "EACCES":
                extra = " (Remember, only root can bind low ports)"
            raise UIError("Error while trying to bind to %s:%s: %s%s"%(
                self.ip, self.port, msg, extra))
        self.sock.listen(backlog)
        self.connectionFactory = connectionFactory
        self.isOpen = 1
        LOG.info("Listening at %s on port %s (fd %s)",
                 ip, port, self.sock.fileno())

    def process(self, r, w, x, cap):
        #XXXX007 do something with x
        con, addr = self.sock.accept()
        LOG.debug("Accepted connection from %s", addr)
        self.connectionFactory(con)
        return self.isOpen,0,self.isOpen,0

    def getStatus(self):
        return self.isOpen,0,self.isOpen

    def shutdown(self):
        LOG.debug("Closing listener connection (fd %s)", self.sock.fileno())
        self.isOpen = 0
        self.sock.close()
        LOG.info("Server connection closed")

    def fileno(self):
        return self.sock.fileno()

class MMTPServerConnection(mixminion.TLSConnection.TLSConnection):
    """A TLSConnection that implements the server side of MMTP."""
    ##
    # Fields:
    #   packetConsumer -- a callback to invoke with each incoming 32K packet
    #   junkCallback -- a callback to invoke whenever we receive padding
    #   rejectCallback -- a callback to invoke whenever we've rejected a packet
    #   protocol -- the negotiated MMTP version
    #   rejectPackets -- flag: do we reject the packets we've received?
    MESSAGE_LEN = 6 + (1<<15) + 20
    PROTOCOL_VERSIONS = ['0.3']
    def __init__(self, sock, tls, consumer, rejectPackets=0, serverName=None):
        if serverName is None:
            addr,port = sock.getpeername()
            serverName = mixminion.ServerInfo.displayServerByAddress(addr,port)
        serverName += " (fd %s)"%sock.fileno()

        mixminion.TLSConnection.TLSConnection.__init__(
            self, tls, sock, serverName)
        EventStats.log.receivedConnection()
        self.packetConsumer = consumer
        self.junkCallback = lambda : None
        self.rejectCallback = lambda : None
        self.protocol = None
        self.rejectPackets = rejectPackets
        self.beginAccepting()

    def onConnected(self):
        self.onRead = self.readProtocol
        self.beginReading()

    def readProtocol(self):
        s = self.getInbufLine(4096,clear=1)
        if s is None:
            return
        elif s == -1:
            self.startShutdown()
            #failed
            return

        self.stopReading()

        m = PROTOCOL_RE.match(s)
        if not m:
            LOG.warn("Bad MMTP protocol string format from %s", self.address)
            #failed
            self.startShutdown()

        protocols = m.group(1).split(",")
        for p in self.PROTOCOL_VERSIONS:
            if p in protocols:
                self.protocol = p
                self.onWrite = self.protocolWritten
                self.beginWriting("MMTP %s\r\n"%p)
                return
        LOG.warn("No common protocols with %s", self.address)
        #failed
        self.startShutdown()

    def protocolWritten(self,n):
        self.onRead = self.onDataRead
        self.onWrite = self.onDataWritten
        self.beginReading()

    def onDataRead(self):
        while self.inbuflen >= self.MESSAGE_LEN:
            data = self.getInbuf(self.MESSAGE_LEN, clear=1)
            control = data[:SEND_CONTROL_LEN]
            pkt = data[SEND_CONTROL_LEN:-DIGEST_LEN]
            digest = data[-DIGEST_LEN:]
            if control == JUNK_CONTROL:
                expectedDigest = sha1(pkt+"JUNK")
                replyDigest = sha1(pkt+"RECEIVED JUNK")
                replyControl = RECEIVED_CONTROL
                isJunk = 1
            elif control == SEND_CONTROL:
                expectedDigest = sha1(pkt+"SEND")
                if self.rejectPackets:
                    replyDigest = sha1(pkt+"REJECTED")
                    replyControl = REJECTED_CONTROL
                else:
                    replyDigest = sha1(pkt+"RECEIVED")
                    replyControl = RECEIVED_CONTROL
                isJunk = 0
            else:
                LOG.warn("Unrecognized command (%r) from %s.  Closing connection.",
                         control, self.address)
                #failed
                self.startShutdown()
                return

            if expectedDigest != digest:
                LOG.warn("Invalid checksum from %s. Closing connection.",
                         self.address)
                #failed
                self.startShutdown()
                return
            else:
                if isJunk:
                    LOG.debug("Link padding received from %s; Checksum valid.",
                              self.address)
                else:
                    LOG.debug("Packet received from %s; Checksum valid.",
                              self.address)

            # Make sure we process the packet before we queue the ack.
            if isJunk:
                self.junkCallback()
            elif self.rejectPackets:
                self.rejectCallback()
            else:
                self.packetConsumer(pkt)

            # Queue the ack.
            self.beginWriting(replyControl+replyDigest)

    def onDataWritten(self, n): pass
    def onTLSError(self): pass
    def onTimeout(self): pass
    def onClosed(self): pass
    def doneWriting(self): pass
    def receivedShutdown(self): pass
    def shutdownFinished(self): pass

#----------------------------------------------------------------------
# Implementation for MMTP.

# The protocol specification to expect.
PROTOCOL_RE          = re.compile("MMTP ([^\s\r\n]+)\r\n")
# Control line for sending a packet
SEND_CONTROL         = "SEND\r\n"
# Control line for sending padding.
JUNK_CONTROL         = "JUNK\r\n"
# Control line for acknowledging a packet
RECEIVED_CONTROL     = "RECEIVED\r\n"
# Control line for refusing a packet
REJECTED_CONTROL     = "REJECTED\r\n"
SEND_CONTROL_LEN     = len(SEND_CONTROL)
RECEIVED_CONTROL_LEN = len(RECEIVED_CONTROL)

#----------------------------------------------------------------------

class DeliverablePacket(mixminion.MMTPClient.DeliverableMessage):
    """Implementation of DeliverableMessage.

       Wraps a ServerQueue.PendingMessage object for a queue holding
       PacketHandler.RelayPacket objects."""
    def __init__(self, pending):
        assert hasattr(pending, 'succeeded')
        assert hasattr(pending, 'failed')
        assert hasattr(pending, 'getMessage')
        self.pending = pending
    def succeeded(self):
        self.pending.succeeded()
    def failed(self,retriable=0):
        self.pending.failed(retriable=retriable)
    def getContents(self):
        return self.pending.getMessage().getPacket()
    def isJunk(self):
        return 0

LISTEN_BACKLOG = 128
class MMTPAsyncServer(AsyncServer):
    """A helper class to invoke AsyncServer, MMTPServerConnection, and
       MMTPClientConnection, with a function to add new connections, and
       callbacks for packet success and failure."""
    ##
    # serverContext: a TLSContext object to use for newly received connections.
    # clientContext: a TLSContext object to use for initiated connections.
    # clientConByAddr: A map from 3-tuples returned by MMTPClientConnection.
    #     getAddr, to MMTPClientConnection objects.
    # certificateCache: A PeerCertificateCache object.
    # listeners: A list of ListenConnection objects.
    # _timeout: The number of seconds of inactivity to allow on a connection
    #     before formerly shutting it down.
    # dnsCache: An instance of mixminion.server.DNSFarm.DNSCache.
    # msgQueue: An instance of MessageQueue to receive notification from DNS
    #     DNS threads.  See _queueSendablePackets for more information.
    # _lock: protects only serverContext.
    # maxClientConnections: Number of client connections we're willing
    #     to have outgoing at any time.  If we try to deliver packets
    #     to a new server, but we already have this many open outgoing
    #     connections, we put the packets in pendingPackets.
    # pendingPackets: A list of tuples to serve as arguments for _sendPackets.

    def __init__(self, config, servercontext):
        AsyncServer.__init__(self)

        self.serverContext = servercontext
        self.clientContext = _ml.TLSContext_new()
        self._lock = threading.Lock()
        self.maxClientConnections = config['Outgoing/MMTP'].get(
            'MaxConnections', 16)
        maxbw = config['Server'].get('MaxBandwidth', None)
        maxbwspike = config['Server'].get('MaxBandwidthSpike', None)
        self.setBandwidth(maxbw, maxbwspike)

        # Don't always listen; don't always retransmit!
        # FFFF Support listening on multiple IPs

        ip4_supported, ip6_supported = getProtocolSupport()
        IP, IP6 = None, None
        if ip4_supported:
            IP = config['Incoming/MMTP'].get('ListenIP')
            if IP is None:
                IP = config['Incoming/MMTP'].get('IP')
            if IP is None:
                IP = "0.0.0.0"
        # FFFF Until we get the non-clique situation is supported, we don't
        # FFFF listen on IPv6.
        #if ip6_supported:
        #    IP6 = config['Incoming/MMTP'].get('ListenIP6')
        #    if IP6 is None:
        #        IP6 = "::"

        port =  config['Incoming/MMTP'].get('ListenPort')
        if port is None:
            port = config['Incoming/MMTP']['Port']

        self.listeners = []
        for (supported, addr, family) in [(ip4_supported,IP,AF_INET),
                                          (ip6_supported,IP6,AF_INET6)]:
            if not supported or not addr:
                continue
            listener = ListenConnection(family, addr, port,
                                        LISTEN_BACKLOG,
                                        self._newMMTPConnection)
            self.listeners.append(listener)
            self.register(listener)

        self._timeout = config['Server']['Timeout'].getSeconds()
        self._optimizeThroughput = config['Server']['OptimizeThroughput']
        self.clientConByAddr = {}
        self.certificateCache = PeerCertificateCache()
        self.dnsCache = None
        self.msgQueue = MessageQueue()
        self.pendingPackets = []

    def connectDNSCache(self, dnsCache):
        """Use the DNSCache object 'DNSCache' to resolve DNS queries for
           this server.
        """
        self.dnsCache = dnsCache

    def setServerContext(self, servercontext):
        """Change the TLS context used for newly received connections.
           Used to rotate keys."""
        self._lock.acquire()
        self.serverContext = servercontext
        self._lock.release()

    def getNextTimeoutTime(self, now=None):
        """Return the time at which we next purge connections, if we have
           last done so at time 'now'."""
        if now is None:
            now = time.time()
        return now + self._timeout

    def _newMMTPConnection(self, sock):
        """helper method.  Creates and registers a new server connection when
           the listener socket gets a hit."""
        # FFFF Check whether incoming IP is allowed!
        self._lock.acquire()
        try:
            tls = self.serverContext.sock(sock, serverMode=1)
        finally:
            self._lock.release()
        sock.setblocking(0)

        addr, port = sock.getpeername()
        hostname = self.dnsCache.getNameByAddressNonblocking(addr)
        name = mixminion.ServerInfo.displayServerByAddress(
            addr, port, hostname)

        con = MMTPServerConnection(sock, tls, self.onPacketReceived,
                                   serverName=name)
        self.register(con)
        return con

    def stopListening(self):
        """Shut down all the listeners for this server.  Does not close open
           connections.
        """
        for listener in self.listeners:
            self.remove(listener)
            listener.shutdown()
        self.listeners = []

    def sendPacketsByRouting(self, routing, deliverable):
        """Given a RoutingInfo object (either an IPV4Info or an MMTPHostInfo),
           and a list of DeliverableMessage objects, start sending all the
           corresponding packets to the corresponding sever, doing a DNS
           lookup first if necessary.
        """
        serverName = mixminion.ServerInfo.displayServerByRouting(routing)
        if isinstance(routing, IPV4Info):
            self._sendPackets(AF_INET, routing.ip, routing.port,
                              routing.keyinfo, deliverable, serverName)
        else:
            assert isinstance(routing, MMTPHostInfo)
            # This function is a callback for when the DNS lookup is over.
            def lookupDone(name, (family, addr, when),
                           self=self, routing=routing, deliverable=deliverable,
                           serverName=serverName):
                if family == "NOENT":
                    LOG.warn("Couldn't resolve %r: %s", name, addr)
                    # The lookup failed, so tell all of the message objects.
                    for m in deliverable:
                        try:
                            m.failed(1)
                        except AttributeError:
                            pass
                else:
                    # We've got an IP address: tell the MMTPServer to start
                    # sending the deliverable packets to that address.
                    self._queueSendablePackets(family, addr,
                                         routing.port, routing.keyinfo,
                                         deliverable, serverName)

            # Start looking up the hostname for the destination, and call
            # 'lookupDone' when we're done.  This is a little fiddly, since
            # 'lookupDone' might get invoked from this thread (if the result
            # is in the cache) or from a DNS thread.
            self.dnsCache.lookup(routing.hostname, lookupDone)

    def _queueSendablePackets(self, family, addr, port, keyID, deliverable,
                              serverName):
        """Helper function: insert the DNS lookup results and list of
           deliverable packets onto self.msgQueue.  Subsequent invocations
           of _sendQueuedPackets will begin sending those packets to their
           destination.

           It is safe to call this function from any thread.
           """
        self.msgQueue.put((family,addr,port,keyID,deliverable,serverName))

    def _sendQueuedPackets(self):
        """Helper function: Find all DNS lookup results and packets in
           self.msgQueue, and begin sending packets to the resulting servers.

           This function should only be called from the main thread.
        """
        while len(self.clientConByAddr) < self.maxClientConnections and self.pendingPackets:
            args = self.pendingPackets.pop(0)
            LOG.debug("Sending %s delayed packets...",len(args[5]))
            self._sendPackets(*args)

        while 1:
            try:
                family,addr,port,keyID,deliverable,serverName = \
                                                self.msgQueue.get(block=0)
            except QueueEmpty:
                return
            self._sendPackets(family,addr,port,keyID,deliverable,serverName)

    def _sendPackets(self, family, ip, port, keyID, deliverable, serverName):
        """Begin sending a set of packets to a given server.

           'deliverable' is a list of objects obeying the DeliverableMessage
           interface.
        """
        try:
            # Is there an existing connection open to the right server?
            con = self.clientConByAddr[(ip,port,keyID)]
        except KeyError:
            pass
        else:
            # No exception: There is an existing connection.  But is that
            # connection currently sending packets?
            if con.isActive():
                LOG.debug("Queueing %s packets on open connection to %s",
                          len(deliverable), con.address)
                for d in deliverable:
                    con.addPacket(d)
                return

        if len(self.clientConByAddr) >= self.maxClientConnections:
            LOG.debug("We already have %s open client connections; delaying %s packets for %s",
                      len(self.clientConByAddr), len(deliverable), serverName)
            self.pendingPackets.append((family,ip,port,keyID,deliverable,serverName))
            return

        try:
            # There isn't any connection to the right server. Open one...
            addr = (ip, port, keyID)
            finished = lambda addr=addr, self=self: self.__clientFinished(addr)
            con = MMTPClientConnection(
                family, ip, port, keyID, serverName=serverName,
                context=self.clientContext, certCache=self.certificateCache,
                optimizeThroughput=self._optimizeThroughput)
            #con.allPacketsSent = finished #XXXX007 wrong!
            con.onClosed = finished
        except (socket.error, MixProtocolError), e:
            LOG.error("Unexpected socket error connecting to %s: %s",
                      serverName, e)
            EventStats.log.failedConnect() #FFFF addr
            for m in deliverable:
                try:
                    m.failed(1)
                except AttributeError:
                    pass
        else:
            # No exception: We created the connection successfully.
            # Thus, register it in clientConByAddr
            assert addr == con.getAddr()
            for d in deliverable:
                con.addPacket(d)

            self.register(con)
            self.clientConByAddr[addr] = con

    def __clientFinished(self, addr):
        """Called when a client connection runs out of packets to send,
           or halts."""
        try:
            del self.clientConByAddr[addr]
        except KeyError:
            LOG.warn("Didn't find client connection to %s in address map",
                     addr)

    def onPacketReceived(self, pkt):
        """Abstract function.  Called when we get a packet"""
        pass

    def process(self, timeout):
        """overrides asyncserver.process to call sendQueuedPackets before
           checking fd status.
        """
        self._sendQueuedPackets()
        AsyncServer.process(self, timeout)
