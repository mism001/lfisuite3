"""
SocksiPy - Python SOCKS module.
[Le reste du header de licence reste inchangé]
"""

__version__ = "1.6.7"

from base64 import b64encode
from collections.abc import Callable
from errno import EOPNOTSUPP, EINVAL, EAGAIN
import functools
from io import BytesIO
import logging
import os
from os import SEEK_CUR
import socket
import struct
import sys

if os.name == "nt":
    try:
        import win_inet_pton
    except ImportError:
        raise ImportError("To run PySocks on Windows you must install win_inet_pton")

log = logging.getLogger(__name__)

PROXY_TYPE_SOCKS4 = SOCKS4 = 1
PROXY_TYPE_SOCKS5 = SOCKS5 = 2
PROXY_TYPE_HTTP = HTTP = 3

PROXY_TYPES = {"SOCKS4": SOCKS4, "SOCKS5": SOCKS5, "HTTP": HTTP}
PRINTABLE_PROXY_TYPES = dict(zip(PROXY_TYPES.values(), PROXY_TYPES.keys()))

_orgsocket = _orig_socket = socket.socket

