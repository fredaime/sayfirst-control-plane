# SPDX-License-Identifier: Apache-2.0
"""The import roots of the test run, and the directory it binds its addresses below.

A package registers itself by existing. `pyproject.toml` globs
`packages/*/tests` into pytest's search paths; the import roots are derived
here instead, because pytest expands a glob in its search paths but reads each
entry of its import-path setting as one literal path, which a glob cannot be.

The lists these replace were shared: every package that joined the repository
had to edit them, so every pair of packages conflicted there by construction,
over a conflict whose resolution was always the union
(`CONTRIBUTING.md`, article 16). `tests/test_package_discovery.py` holds this
file, and fails naming any package it does not reach.

The second thing derived here is where the run puts its temporary files, for
the reasons `_run_root` gives; `tests/test_socket_address_budget.py` holds
that one.
"""

from __future__ import annotations

import getpass
import os
import secrets
import sys
import tempfile
from hashlib import blake2s
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent


def _register_source_roots() -> None:
    """Put every `packages/*/src` on the import path, ahead of the environment."""
    roots = sorted(item for item in REPOSITORY.glob("packages/*/src") if item.is_dir())
    for root in reversed(roots):
        entry = str(root)
        if entry not in sys.path:
            sys.path.insert(0, entry)


_register_source_roots()


def _default_tmp_root() -> str:
    """The root `pytest` would bind below if nothing here touched `--basetemp`.

    This is `_pytest.tmpdir.TempPathFactory`'s own default —
    `<tempdir>/pytest-of-<user>/pytest-<n>` — sized closely enough to decide
    with: `n` is read as a single digit, the case on a runner that starts
    clean. Reading it as one digit only ever undercounts the default's
    length, so this can miss a host it should have caught by one digit's
    worth of bytes; it can never invent a problem a short host does not have.
    """
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    tmp = os.path.realpath(tempfile.gettempdir())
    return os.path.join(tmp, f"pytest-of-{user}", "pytest-0")


def _short_writable_root() -> str | None:
    """A fresh, short directory: `/tmp` first, else the shorter of `$TMPDIR`, `/var/tmp`.

    The leaf is four random hex characters, the same length `_run_root`'s own
    deterministic one is — not `tempfile.mkdtemp`'s default, which is nearly
    twice as long and left `tests/test_socket_address_budget.py` failing by a
    single byte once this root was itself what that guard measured. A
    collision is handled by trying again, the way `mkdtemp` does; four hex
    characters is small enough that this is worth naming rather than assuming.
    """
    if os.path.isdir("/tmp") and os.access("/tmp", os.W_OK):
        base = "/tmp"
    else:
        others = [
            candidate
            for candidate in (os.environ.get("TMPDIR"), "/var/tmp")
            if candidate and os.path.isdir(candidate) and os.access(candidate, os.W_OK)
        ]
        if not others:
            return None
        base = min(others, key=len)
    for _ in range(64):
        candidate = Path(base) / f"sf-{secrets.token_hex(2)}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return str(candidate)
    return None


def _short_basetemp_for_a_long_default() -> str | None:
    """A short `--basetemp`, decided by length alone, asked for before `_run_root` is.

    This was written to live in `pytest_load_initial_conftests`, which is the
    hook pytest itself documents for changing `--basetemp` before its `tmpdir`
    plugin reads the default (`_pytest/hookspec.py`). It cannot: that same
    docstring also says, in so many words, "this hook is not called for
    conftest files" — and a conftest file is exactly what this is. Proven the
    same way `_run_root`'s own claims are proven rather than assumed: a debug
    marker placed inside a `pytest_load_initial_conftests` defined here was
    never written, under the same long `TMPDIR` this function is exercised
    against below. `pytest_configure` is what is left, and what `_run_root`
    already uses; article 2 records the correction so a future reader does not
    spend the same afternoon finding it again.

    Unlike `_run_root`, this asks only about length, never about protection —
    it exists for the host where the protection question itself cannot be
    answered (a `_AclUnreadable` macOS ACL read, say), which is the one case
    `_run_root` must decline on rather than guess about, leaving the daemon to
    start below the long default anyway. Left there, it refuses with
    `socket_path_too_long: socket.path is 131 bytes, the limit is 104`, or the
    kernel refuses first, from inside a fixture that had already been built,
    with `OSError: AF_UNIX path too long`. Either text is how a reader who did
    not read this file first arrives at it.

    The margin asked for is forty bytes — a test's own directory plus
    `runN/daemon.sock` — measured against 104, the stricter of the two limits
    this repository supports, so a host with the shorter limit is the one it
    is checked against. A short default, which is every Linux host measured so
    far, leaves this returning `None`, and `pytest_configure` proceeds to
    `_run_root` exactly as it did before this existed.
    """
    margin = 104 - len(_default_tmp_root())
    if margin >= 40:
        return None
    return _short_writable_root()


def _run_root() -> Path | None:
    """The shortest protected directory this run can bind its addresses below.

    Two properties of a temporary root are load-bearing here, and `pytest`'s
    default root — `$TMPDIR/pytest-of-<user>/pytest-<n>` — is chosen for
    neither of them.

    The first is length. A local address is a `sun_path` of 108 bytes on Linux
    and 104 on macOS, NUL included (article 6). The default root spends
    thirty-two of them before a test has written anything, and one more digit
    in the run counter spends another; the acceptance suites then bind one
    address per scenario below it. That is not a suite that passes, it is a
    suite that passes here, and article 13 publishes this contract so that
    somebody else can run it.

    The second is protection. The daemon refuses a policy authority, and
    refuses to bind, when anyone but its own principal and root could write the
    path or a directory on it (articles 6 and 8) — and a temporary root a
    contributor made under the common umask `0002` is group-writable, so every
    test that starts a daemon below it is refused for a reason that is about
    the host rather than about the code. A suite cannot make an ancestor it
    does not own protected; it can decline to build below one. So the daemon's
    own rule is what chooses the root, rather than a second reading of it
    written here (`access/effective_access.py`).

    `TMPDIR` is honoured when it can hold the run, because a contributor who
    set it meant it; the fallbacks are tried only when it cannot, and
    `pytest_report_header` says which was taken. An explicit `--basetemp` is
    never overridden: that is the operator saying where, and being told the
    consequence by `tests/test_socket_address_budget.py` is the right order.
    """
    from sayfirst_contract.binding.http_unix_socket.addresses import (
        SUN_PATH_LIMITS,
        root_leaves_the_margin,
    )
    from sayfirst_control_plane.access.effective_access import protection
    from sayfirst_control_plane.ports.policy_store import ProtectionState

    leaf = f"sf-{blake2s(str(REPOSITORY).encode('utf-8'), digest_size=2).hexdigest()}"
    allowed_owners = frozenset({0, os.geteuid()})
    seen = set()
    for base in (tempfile.gettempdir(), os.environ.get("XDG_RUNTIME_DIR"), "/tmp"):
        if not base or base in seen:
            continue
        seen.add(base)
        if not Path(base).is_dir():
            continue
        candidate = Path(base) / leaf
        if not all(
            root_leaves_the_margin(candidate, platform=platform) for platform in SUN_PATH_LIMITS
        ):
            continue
        try:
            candidate.mkdir(mode=0o700, exist_ok=True)
        except OSError:
            continue
        verdict = protection(
            candidate,
            allowed_owner_uids=allowed_owners,
            allowed_write_gids=frozenset(),
        )
        if verdict.kind is ProtectionState.PROTECTED:
            return candidate
    return None


#: Where this run bound its addresses, and why, for `pytest_report_header`.
_RUN_ROOT_NOTE = "run root: --basetemp as given"


def pytest_configure(config) -> None:  # type: ignore[no-untyped-def]
    """Choose a run root that fits `sun_path` and that the daemon will accept."""
    global _RUN_ROOT_NOTE
    if config.option.basetemp is not None:
        return
    short_root = _short_basetemp_for_a_long_default()
    if short_root is not None:
        config.option.basetemp = short_root
        _RUN_ROOT_NOTE = (
            f"run root: {short_root} — the default `pytest` would have used left less "
            "than forty bytes for `runN/daemon.sock`; chosen by length alone, ahead of "
            "`_run_root`'s protection check (`test_socket_paths_fit_the_platform_limit.py`)"
        )
        return
    root = _run_root()
    if root is None:
        _RUN_ROOT_NOTE = (
            "run root: no short, protected directory was found; "
            "the default is used and tests/test_socket_address_budget.py says what it costs"
        )
        return
    config.option.basetemp = str(root)
    from sayfirst_contract.binding.http_unix_socket.addresses import (
        ADDRESS_MARGIN_BYTES,
        STRICTEST_SUN_PATH_LIMIT,
        address_budget,
    )

    _RUN_ROOT_NOTE = (
        f"run root: {root} — a test below it may reach {address_budget(root)} bytes of "
        f"sun_path, {STRICTEST_SUN_PATH_LIMIT - address_budget(root)} short of the "
        f"strictest supported limit, and the margin is {ADDRESS_MARGIN_BYTES}"
    )


def pytest_report_header() -> str:
    """Say where this run binds, so the number is read rather than assumed."""
    return _RUN_ROOT_NOTE
