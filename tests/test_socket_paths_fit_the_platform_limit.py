# SPDX-License-Identifier: Apache-2.0
"""Article 6: a test's own socket address fits inside the strictest AF_UNIX limit.

104 is macOS's `sun_path` size, NUL included
(`packages/contract/.../http_unix_socket/addresses.py`); 100 is that limit with
four bytes of margin, the same margin `ADDRESS_MARGIN_BYTES` there keeps, so
this guard fails while shortening the leaf is still enough, rather than at the
moment `bind` itself refuses. Where the default `pytest` root would not leave
this much room, the root `conftest.py`'s `pytest_load_initial_conftests` hook
is what makes it true anyway; a failure here means that hook did not run, or
did not shorten the root enough.
"""

from __future__ import annotations

from pathlib import Path


def test_a_run_socket_fits_the_af_unix_limit_on_every_supported_platform(tmp_path: Path) -> None:
    """The address a daemon guard actually binds — `runN/daemon.sock` — stays under the limit."""
    address = tmp_path / "run0" / "daemon.sock"
    assert len(str(address).encode()) <= 100
