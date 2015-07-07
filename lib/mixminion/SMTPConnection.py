import smtplib
import socket
import errno
import re


class AsyncSMTP(smtplib.SMTP):

    def __init__(self, host='', port=0, local_hostname=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        self.want_read = 0
        self.open = 0
        self._write_buf = b''
        self._reponse = b''
        self._callback_queue = []

        self.timeout = timeout
        self.esmtp_features = {}
        if host:
            def after_connect(code, msg):
                if code != 220:
                    raise SMTPConnectError(code, msg)
            self.connect(host, port, callback=after_connect)
        if local_hostname is not None:
            self.local_hostname = local_hostname
        else:
            # RFC 2821 says we should use the fqdn in the EHLO/HELO verb, and
            # if that can't be calculated, that we should use a domain literal
            # instead (essentially an encoded IP address like [A.B.C.D]).
            self.local_hostname = socket.getfqdn()

    @property
    def want_write(self):
        return 1 if self._write_buf else 0

    def _get_socket(self, host, port, timeout):
        s = socket.socket()
        s.setblocking(0)
        try:
            s.connect((host, port))
        except socket.error as e:
            if e.errno != errno.EINPROGRESS:
                raise
        self.open = 1
        self.want_read = 1
        return s

    def send(self, s):
        if isinstance(s, str):
            s = s.encode("ascii")
        self._write_buf += s
        self.want_read = 1

    def fileno(self):
        return self.sock.fileno()

    def close(self):
        smtplib.SMTP.close(self)
        self.open = 0

    def connect(self, host='localhost', port=0, callback=None):
        if not port and (host.find(':') == host.rfind(':')):
            i = host.rfind(':')
            if i >= 0:
                host, port = host[:i], host[i + 1:]
                try:
                    port = int(port)
                except ValueError:
                    raise socket.error, "nonnumeric port"
        if not port:
            port = self.default_port
        if self.debuglevel > 0:
            print>>stderr, 'connect:', (host, port)
        self.sock = self._get_socket(host, port, self.timeout)

        def after_connected(code, msg):
            if self.debuglevel > 0:
                print>>stderr, "connect:", msg
            if callback:
                callback(code, msg)
        self.getreply(callback=after_connected)

    def _read_data(self):
        self._reponse += self.sock.recv(65536)
        if '\r\n' not in self._reponse:
            return
        resp = []
        for line in self._reponse.splitlines():
            resp.append(line[4:].strip(b' \t\r\n'))
            code = line[:3]
            # Check that the error code is syntactically correct.
            # Don't attempt to read a continuation line if it is broken.
            try:
                errcode = int(code)
            except ValueError:
                errcode = -1
                break
            # Check if multiline response.
            if line[3:4] != b"-":
                break
        else:
            return  # We want to read more
        errmsg = b"\n".join(resp)
        self._reponse = ''
        self.want_read = 0
        self._callback_queue.pop(0)(errcode, errmsg)

    def process(self, r, w, x, cap):
        assert self.sock
        if r:
            self._read_data()

        if w:
            try:
                sent = self.sock.send(self._write_buf)
                self._write_buf = self._write_buf[sent:]
                self.want_read = 1
            except OSError:
                self.close()
                raise smtplib.SMTPServerDisconnected('Server not connected')
            except socket.error as e:
                if e.errno != errno.EAGAIN:
                    raise
        if x:
            raise Exception("SMTP client socket exception: %d" % x)

        return self.want_read, self.want_write, self.open, 0

    def tryTimeout(self, cutoff):
        # Whatever, just ignore the damn thing
        return False

    def starttls(self, *args, **kw):
        raise NotImplementedError("StartTLS not supported")

    def getreply(self, callback):
        self._callback_queue.append(callback)

    def getStatus(self):
        return self.want_read, self.want_write, self.open

    def ehlo_or_helo_if_needed(self, callback=None):

        def after_helo(code, resp):
            if not (200 <= code <= 299):
                raise SMTPHeloError(code, resp)
            elif callback:
                callback(None, None)

        def after_ehlo(code, resp):
            if not (200 <= code <= 299):
                self.helo(callback=after_helo)
            elif callback:
                callback(None, None)

        self.ehlo(callback=after_ehlo)

    def sendmail(self, from_addr, to_addrs, msg, mail_options=[], rcpt_options=[], callback=None):
        senderrs = {}
        rcpt_count = [0]

        def after_rset(code, resp, x, y):
            raise SMTPSenderRefused(code, resp, from_addr)

        def after_rset_senderrs(code, resp):
            raise SMTPRecipientsRefused(senderrs)

        def after_data(code, resp):
            if code != 250:
                self.rset(callback=after_rset)
                raise SMTPDataError(code, resp)
            # if we got here then somebody got our mail
            if callback:
                callback(code, resp)

        def after_rcpt(code, resp):
            rcpt_count[0] += 1
            if (code != 250) and (code != 251):
                senderrs[each] = (code, resp)
            if rcpt_count[0] == len(to_addrs):
                if len(senderrs) == len(to_addrs):
                    # the server refused all our recipients
                    self.rset(
                        callback=after_rset_senderrs)
                self.data(msg, callback=after_data)

        def after_mail(code, resp):
            if code != 250:
                self.rset(callback=lambda x, y: after_rset(code, resp, x, y))

            senderrs = {}
            local_to_addrs = to_addrs
            if isinstance(local_to_addrs, basestring):
                local_to_addrs = [local_to_addrs]
            for each in local_to_addrs:
                self.rcpt(each, rcpt_options, callback=after_rcpt)

        def after_ehlo(code, resp):
            esmtp_opts = []
            if self.does_esmtp:
                # Hmmm? what's this? -ddm
                # self.esmtp_features['7bit']=""
                if self.has_extn('size'):
                    esmtp_opts.append("size=%d" % len(msg))
                for option in mail_options:
                    esmtp_opts.append(option)

            self.mail(from_addr, esmtp_opts, callback=after_mail)
        self.ehlo_or_helo_if_needed(callback=after_ehlo)

    def docmd(self, cmd, args="", callback=lambda x, y: None):
        """Send a command, and return its response code."""
        self.putcmd(cmd, args)
        self.getreply(callback=callback)

    # std smtp commands
    def helo(self, name='', callback=None):
        """SMTP 'helo' command.
        Hostname to send for this command defaults to the FQDN of the local
        host.
        """

        def after_cmd(code, msg):
            self.helo_resp = msg
            if callback:
                callback(code, msg)

        self.putcmd("helo", name or self.local_hostname)
        self.getreply(callback=after_cmd)

    def ehlo(self, name='', callback=None):
        """ SMTP 'ehlo' command.
        Hostname to send for this command defaults to the FQDN of the local
        host.
        """

        def after_cmd(code, msg):
            # According to RFC1869 some (badly written)
            # MTA's will disconnect on an ehlo. Toss an exception if
            # that happens -ddm
            if code == -1 and len(msg) == 0:
                self.close()
                raise SMTPServerDisconnected("Server not connected")
            self.ehlo_resp = msg
            if code != 250:
                if callback:
                    callback(code, msg)
                else:
                    return
            self.does_esmtp = 1
            #parse the ehlo response -ddm
            resp = self.ehlo_resp.split('\n')
            del resp[0]
            for each in resp:
                # To be able to communicate with as many SMTP servers as possible,
                # we have to take the old-style auth advertisement into account,
                # because:
                # 1) Else our SMTP feature parser gets confused.
                # 2) There are some servers that only advertise the auth methods we
                #    support using the old style.
                auth_match = smtplib.OLDSTYLE_AUTH.match(each)
                if auth_match:
                    # This doesn't remove duplicates, but that's no problem
                    self.esmtp_features["auth"] = self.esmtp_features.get("auth", "") \
                            + " " + auth_match.groups(0)[0]
                    continue

                # RFC 1869 requires a space between ehlo keyword and parameters.
                # It's actually stricter, in that only spaces are allowed between
                # parameters, but were not going to check for that here.  Note
                # that the space isn't present if there are no parameters.
                m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*) ?', each)
                if m:
                    feature = m.group("feature").lower()
                    params = m.string[m.end("feature"):].strip()
                    if feature == "auth":
                        self.esmtp_features[feature] = self.esmtp_features.get(feature, "") \
                                + " " + params
                    else:
                        self.esmtp_features[feature] = params
            if callback:
                callback(code, msg)

        self.esmtp_features = {}
        self.putcmd(self.ehlo_msg, name or self.local_hostname)
        self.getreply(callback=after_cmd)

    def rset(self, callback=None):
        """SMTP 'rset' command -- resets session."""
        self.docmd("rset", callback=callback)

    def rcpt(self, recip, options=[], callback=None):
        """SMTP 'rcpt' command -- indicates 1 recipient for this mail."""
        optionlist = ''
        if options and self.does_esmtp:
            optionlist = ' ' + ' '.join(options)
        self.putcmd("rcpt", "TO:%s%s" % (smtplib.quoteaddr(recip), optionlist))
        self.getreply(callback=callback)

    def mail(self, sender, options=[], callback=None):
        """SMTP 'mail' command -- begins mail xfer session."""
        optionlist = ''
        if options and self.does_esmtp:
            optionlist = ' ' + ' '.join(options)
        self.putcmd("mail", "FROM:%s%s" % (smtplib.quoteaddr(sender), optionlist))
        self.getreply(callback=callback)

    def data(self, msg, callback=None):
        """SMTP 'DATA' command -- sends message data to server.

        Automatically quotes lines beginning with a period per rfc821.
        Raises SMTPDataError if there is an unexpected reply to the
        DATA command; the return value from this method is the final
        response code received when the all data is sent.
        """
        def after_send(code, msg):
            if self.debuglevel > 0:
                print>>stderr, "data:", (code, msg)
            if callback:
                callback(code, msg)

        def after_cmd(code, repl):
            if self.debuglevel > 0:
                print>>stderr, "data:", (code, repl)
            if code != 354:
                raise SMTPDataError(code, repl)
            else:
                q = smtplib.quotedata(msg)
                if q[-2:] != smtplib.CRLF:
                    q = q + smtplib.CRLF
                q = q + "." + smtplib.CRLF
                self.send(q)
                self.getreply(callback=after_send)
        self.putcmd("data")
        self.getreply(callback=after_cmd)

    def quit(self, callback=None):

        def cb(code, resp):
            self.close()
            if callback:
                callback(code, resp)
        self.docmd("quit", callback=cb)
