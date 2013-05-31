"""OpenSSL-based implementation of Connection.
"""

from sys import exc_clear
from gevent.socket import wait_read, wait_write
from OpenSSL.SSL import *
from OpenSSL.SSL import WantReadError, WantWriteError, ZeroReturnError
from OpenSSL.SSL import Connection as _Connection


class Connection(_Connection):

    def __init__(self, context, sock):
        _Connection.__init__(self, context, sock)
        self._context = context
        self._sock = sock
        self._timeout = sock.gettimeout()
        self._makefile_refs = 0

    def accept(self):
        sock, addr = self._sock.accept()
        client = Connection(sock._context, sock)
        return client, addr

    def do_handshake(self):
        while True:
            try:
                _Connection.do_handshake(self)
                break
            except WantReadError:
                exc_clear()
                wait_read(self._sock.fileno(), timeout=self._timeout)
            except WantWriteError:
                exc_clear()
                wait_write(self._sock.fileno(), timeout=self._timeout)

    def connect(self, *args, **kwargs):
        while True:
            try:
                _Connection.connect(self, *args, **kwargs)
                break
            except WantReadError:
                exc_clear()
                wait_read(self._sock.fileno(), timeout=self._timeout)
            except WantWriteError:
                exc_clear()
                wait_write(self._sock.fileno(), timeout=self._timeout)

    def send(self, data, flags=0):
        while True:
            try:
                _Connection.send(self, data, flags)
                break
            except WantReadError:
                exc_clear()
                wait_read(self._sock.fileno(), timeout=self._timeout)
            except WantWriteError:
                exc_clear()
                wait_write(self._sock.fileno(), timeout=self._timeout)
            except SysCallError as e:
                if e[0] == -1 and not data:
                    # errors when writing empty strings are expected and can be ignored
                    return 0
                raise

    def recv(self, bufsiz, flags=0):
        pending = _Connection.pending(self)
        if pending:
            return _Connection.recv(min(pending, bufsiz))
        while True:
            try:
                return _Connection.recv(self, buflen, flags)
            except WantReadError:
                exc_clear()
                wait_read(self._sock.fileno(), timeout=self._timeout)
            except WantWriteError:
                exc_clear()
                wait_write(self._sock.fileno(), timeout=self._timeout)
            except ZeroReturnError:
                return ''

    def read(self, bufsiz, flags=0):
        return self.recv(bufsiz, flags)

    def write(self, buf, flags=0):
        return self.sendall(buf, flags)
