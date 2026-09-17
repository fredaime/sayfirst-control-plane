# SPDX-License-Identifier: Apache-2.0
"""The HTTP binding served over the host Unix socket."""

from .client import SocketClient, UnsupportedPlatform
from .replay import SocketHarness
from .routes import (
    ACCEPT_HEADER,
    DOCUMENT_MEDIA_TYPE,
    ROUTES,
    STREAM_MEDIA_TYPE,
    Route,
    selects_stream,
)

__all__ = [
    "ACCEPT_HEADER",
    "DOCUMENT_MEDIA_TYPE",
    "ROUTES",
    "STREAM_MEDIA_TYPE",
    "Route",
    "SocketClient",
    "SocketHarness",
    "UnsupportedPlatform",
    "selects_stream",
]
