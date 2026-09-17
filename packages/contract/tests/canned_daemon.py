# SPDX-License-Identifier: Apache-2.0
"""A real local HTTP peer with a canned response and a request log."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn, UnixStreamServer
from threading import Thread


@contextmanager
def answering(
    socket_path: Path,
    status: int,
    document: object,
    *,
    close_after_each: bool = False,
    drop_posts: bool = False,
    drop_gets: bool = False,
    raw_body: bytes | None = None,
    record_bodies: list[bytes] | None = None,
) -> Iterator[list[tuple[str, str]]]:
    """Serve `document` with `status` to every request, recording (method, path).

    With `close_after_each`, every answer carries `Connection: close` and the
    server hangs up after it — what the daemon does after an answer an adapter
    wrote itself, and what a client holding a keep-alive must survive. With
    `drop_posts`, a POST is received and recorded and the server hangs up
    without answering it — the one case in which a client must NOT put the
    request again, because the far end may have recorded it. `drop_gets` is the
    same hang-up on a read, and exists to hold the other half of that rule: a
    read whose reply was lost decided nothing, so it keeps the retryability the
    registry publishes and a client may ask again.

    With `raw_body`, those bytes are served instead of `document` encoded. A
    body a client must survive is not always one this side can build: a reply
    nested deeper than the encoder's own limit is the case that needs it.

    With `record_bodies`, the bytes of each request are appended to that list.
    What was recorded is the only way a case can say what a client PUT, as
    against what it received back, and a POST is the request where the two are
    different questions. The yielded log keeps its (method, path) shape so that
    no case which never asked about a body has to say so.
    """
    requests: list[tuple[str, str]] = []
    payload = json.dumps(document).encode("utf-8") if raw_body is None else raw_body

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.command, self.path))
            if record_bodies is not None:
                record_bodies.append(body)
            if (drop_posts and self.command == "POST") or (drop_gets and self.command == "GET"):
                self.close_connection = True
                return
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if close_after_each:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(payload)

        do_POST = do_GET

        def log_message(self, format: str, *args: object) -> None:
            pass

    class Server(ThreadingMixIn, UnixStreamServer):
        daemon_threads = True

    with Server(str(socket_path), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield requests
        finally:
            server.shutdown()
            thread.join()
            socket_path.unlink(missing_ok=True)
