"""OpenSSL-based implementation of Connection.
"""
from functools import wraps
from sys import exc_clear
from gevent.socket import wait_read
from gevent.socket import wait_write
from OpenSSL.SSL import Connection
from OpenSSL.SSL import WantReadError
from OpenSSL.SSL import WantWriteError
from OpenSSL.SSL import SysCallError
from OpenSSL.SSL import ZeroReturnError


def gevent_wrap(func):
    @wraps(func)
    def wrapped(self, *args, **kwargs):
        while True:
            try:
                return func(self, *args, **kwargs)
            except WantReadError:
                exc_clear()
                wait_read(self.fileno(), timeout=self.get_context().get_timeout())
            except WantWriteError:
                exc_clear()
                wait_write(self.fileno(), timeout=self.get_context().get_timeout())

    return wrapped


def wrap_send(func):
    @wraps(func)
    def wrapped(self, data, *args, **kwargs):
        try:
            return func(self, data, *args, **kwargs)
        except SysCallError as e:
            if e[0] == -1 and not data:
                # errors when writing empty strings are expected and can be ignored
                return 0
            raise

    return wrapped


def wrap_recv(func):
    @wraps(func)
    def wrapped(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except ZeroReturnError:
            return ""

    return wrapped


def patch_openssl():
    Connection.do_handshake = gevent_wrap(Connection.do_handshake)
    Connection.connect = gevent_wrap(Connection.connect)
    Connection.send = gevent_wrap(wrap_send(Connection.send))
    Connection.recv = gevent_wrap(wrap_recv(Connection.recv))
