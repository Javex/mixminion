import sys
sys.path[0:0] = ['/home/javex/.shadow/lib/python2.7/site-packages']
import urllib2
import httplib
import socket
import StringIO
import errno
import mixminion.AsyncUtils


class AsyncHTTPResponse(httplib.HTTPResponse):

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False):
        self.debuglevel = debuglevel
        self.strict = strict
        self._method = method
        self.data = ''
        self._response_data = ''

        self.msg = None

        # from the Status-Line of the response
        self.version = httplib._UNKNOWN  # HTTP-Version
        self.status = httplib._UNKNOWN  # Status-Code
        self.reason = httplib._UNKNOWN  # Reason-Phrase

        self.chunked = httplib._UNKNOWN
        self.chunk_left = httplib._UNKNOWN
        self.length = httplib._UNKNOWN
        self.will_close = httplib._UNKNOWN
        self._sock = sock
        self._read_fn = self._read_header_data
        self.close_connection = 0
        self.want_read = 1
        self.open = 1

    def _read_header_data(self, r=0):
        new_data = self._sock.recv(65537)
        if not new_data:
            self.close_connection = 1
        self._response_data += new_data
        header_end = self._response_data.find('\r\n\r\n')
        if header_end != -1:
            self._raw_headers = self._response_data[:header_end].splitlines()
            self._response_data = self._response_data[header_end + 4:]
            self.want_read = 0
            self._handle_headers()
        else:
            self.want_read = 1

    def _handle_headers(self):
        self.raw_requestline = self._raw_headers[0]
        if len(self.raw_requestline) > 65536:
            self.requestline = ''
            self.request_version = ''
            self.command = ''
            self.send_error(414)
            return
        if not self.raw_requestline:
            self.close_connection = 1
            return
        self.fp = StringIO.StringIO('\r\n'.join(self._raw_headers))
        self.begin()
        self.fp.close()
        self.headers = self.msg
        self._read_fn = self._read_data
        self._read_data()

    def _read_data(self, r=0):
        if r:
            self._response_data += self._sock.recv(65536)
        expected_length = int(self.headers['Content-Length'])
        if expected_length > len(self._response_data):
            self.want_read = 1
            return
        self.close()
        self.open = 0
        self.want_read = 0

    def read(self, *args, **kw):
        if self.want_read:
            raise Exception("Not done")
        return self._response_data

    def process(self, r, w, x):
        if r:
            self._read_fn(r)
        if w:
            raise Exception("Not expecting to write!")
        return self.want_read, 0, self.open, 0


class AsyncHTTPConnection(httplib.HTTPConnection):

    response_class = AsyncHTTPResponse

    def __init__(self, *args, **kw):
        self._out_data = ''
        self._read_fn = None
        self.want_read = 0
        self.open = 0
        self.response = None
        httplib.HTTPConnection.__init__(self, *args, **kw)

    @property
    def want_write(self):
        return 1 if self._out_data else 0

    def connect(self):
        ainfo = socket.getaddrinfo(
            self.host, self.port, socket.AF_INET,
            socket.SOCK_STREAM, socket.IPPROTO_TCP)
        family, socktype, proto, _, sockaddr = ainfo[0]
        self.sock = socket.socket(family, socktype, proto)
        self.sock.setblocking(0)
        try:
            self.sock.connect(sockaddr)
        except socket.error as e:
            if e[0] != errno.EINPROGRESS:
                raise
        if self._tunnel_host:
            self._tunnel()
        self.open = 1

    def send(self, data):
        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise httplib.NotConnected()
        if self.debuglevel > 0:
            print "send:", repr(data)
        blocksize = 8192
        if hasattr(data, 'read') and not isinstance(data, array):
            if self.debuglevel > 0:
                print "sendIng a read()able"
            datablock = data.read(blocksize)
            while datablock:
                self._out_data += datablock
                datablock = data.read(blocksize)
        else:
            self._out_data += data

    def getresponse(self, buffering=False):
        "Get the response from the server."
        if self.response:
            return self.response

        # if a prior response has been completed, then forget about it.
        if self.response and self.response.isclosed():
            self.response = None

        #
        # if a prior response exists, then it must be completed (otherwise, we
        # cannot read this response's header to determine the connection-close
        # behavior)
        #
        # note: if a prior response existed, but was connection-close, then the
        # socket and response were made independent of this HTTPConnection
        # object since a new request requires that we open a whole new
        # connection
        #
        # this means the prior response had one of two states:
        #   1) will_close: this connection was reset and the prior socket and
        #                  response operate independently
        #   2) persistent: the response was retained and we await its
        #                  isclosed() status to become true.
        #
        # if self.__state != _CS_REQ_SENT or self.response:
        #     raise ResponseNotReady()

        args = (self.sock,)
        kwds = {"strict": self.strict, "method": self._method}
        if self.debuglevel > 0:
            args += (self.debuglevel,)
        if buffering:
            # only add this keyword if non-default, for compatibility with
            # other response_classes.
            kwds["buffering"] = True
        response = self.response_class(*args, **kwds)
        # self.__state = _CS_IDLE
        self.response = response
        self.want_read = 1
        return response

    def process(self, r, w, x, cap):
        if r:
            if not self.response:
                raise Exception("Need response to read")
            return self.response.process(r, w, x)
        if w and self._out_data:
            sent = self.sock.send(self._out_data)
            self._out_data = self._out_data[sent:]
        return self.want_read, self.want_write, self.open, 0

    def getStatus(self):
        return self.want_read, self.want_write, self.open

    def fileno(self):
        return self.sock.fileno()


class HTTPHandler(urllib2.HTTPHandler):

    def http_open(self, req):
        return self.do_open(AsyncHTTPConnection, req)

    def do_open(self, http_class, req):
        """Return an addinfourl object for the request, using http_class.

        http_class must implement the HTTPConnection API from httplib.
        The addinfourl return value is a file-like object.  It also
        has methods and attributes including:
            - info(): return a mimetools.Message object for the headers
            - geturl(): return the original request URL
            - code: HTTP status code
        """
        host = req.get_host()
        if not host:
            raise urllib2.URLError('no host given')

        h = http_class(host, timeout=req.timeout) # will parse host:port
        h.set_debuglevel(self._debuglevel)

        headers = dict(req.unredirected_hdrs)
        headers.update(dict((k, v) for k, v in req.headers.items()
                            if k not in headers))

        # We want to make an HTTP/1.1 request, but the addinfourl
        # class isn't prepared to deal with a persistent connection.
        # It will try to read all remaining data from the socket,
        # which will block while the server waits for the next request.
        # So make sure the connection gets closed after the (only)
        # request.
        headers["Connection"] = "close"
        headers = dict(
            (name.title(), val) for name, val in headers.items())

        if req._tunnel_host:
            tunnel_headers = {}
            proxy_auth_hdr = "Proxy-Authorization"
            if proxy_auth_hdr in headers:
                tunnel_headers[proxy_auth_hdr] = headers[proxy_auth_hdr]
                # Proxy-Authorization should not be sent to origin
                # server.
                del headers[proxy_auth_hdr]
            h.set_tunnel(req._tunnel_host, headers=tunnel_headers)

        try:
            h.request(req.get_method(), req.get_selector(), req.data, headers)
        except socket.error, err: # XXX what error?
            h.close()
            raise urllib2.URLError(err)
        else:
            try:
                r = h.getresponse(buffering=True)
            except TypeError: # buffering kw not supported
                r = h.getresponse()
        return h

        # Pick apart the HTTPResponse object to get the addinfourl
        # object initialized properly.

        # Wrap the HTTPResponse object in socket's file object adapter
        # for Windows.  That adapter calls recv(), so delegate recv()
        # to read().  This weird wrapping allows the returned object to
        # have readline() and readlines() methods.

        # XXX It might be better to extract the read buffering code
        # out of socket._fileobject() and into a base class.

        r.recv = r.read
        fp = socket._fileobject(r, close=True)

        resp = addinfourl(fp, r.msg, req.get_full_url())
        resp.code = r.status
        resp.msg = r.reason
        return resp
