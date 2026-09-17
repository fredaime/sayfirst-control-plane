# SPDX-License-Identifier: Apache-2.0
"""Article 6, rules C1 and C4: every connection is verified on its own terms."""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sayfirst_contract.problems import ProblemCode
from sayfirst_contract.transport.socket_client import (
    SocketClientProblem,
    SocketProfile,
    connect,
    expected_principal_uid,
)
from sayfirst_testing.platforms import OS_REAL_PLATFORMS, requires_platforms

ME = os.geteuid()
STRANGER = ME + 1


@contextmanager
def listening(address: Path) -> Iterator[socket.socket]:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(address))
        listener.listen(4)
        listener.settimeout(5)
        yield listener
    finally:
        listener.close()
        address.unlink(missing_ok=True)


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_system_reconnect_resolves_its_expected_principal_again(tmp_path: Path) -> None:
    """Rule C1: the account is resolved at connect time, on every connect."""
    address = tmp_path / "daemon.sock"
    lookups: list[str] = []
    account = {"uid": ME}

    def account_uid(name: str) -> int | None:
        lookups.append(name)
        return account["uid"]

    profile = SocketProfile(str(address), mode="system", daemon_user="sayfirst")
    with listening(address):
        connection = connect(profile, account_uid=account_uid)
        assert lookups == ["sayfirst"]
        assert connection.expected_uid == ME
        assert connection.verified

        # The account the profile names is remapped to another uid. The
        # listener has not changed, so the next connection must refuse it.
        account["uid"] = STRANGER
        connection.http.sock = None
        with pytest.raises(SocketClientProblem) as refusal:
            connection.reconnect()
        assert refusal.value.problem.code is ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL
        assert lookups == ["sayfirst", "sayfirst"]
        assert str(STRANGER) in refusal.value.problem.message
        connection.close()


@requires_platforms(*OS_REAL_PLATFORMS)
def test_a_reconnect_is_authorised_on_the_credential_it_read(tmp_path: Path) -> None:
    """Rule C4: never the first connection's uid, and never a cached verdict."""
    address = tmp_path / "daemon.sock"
    account = {"uid": STRANGER}

    def account_uid(name: str) -> int | None:
        return account["uid"]

    profile = SocketProfile(str(address), mode="system", daemon_user="sayfirst")
    with listening(address):
        with pytest.raises(SocketClientProblem) as refusal:
            connect(profile, account_uid=account_uid)
        assert refusal.value.problem.code is ProblemCode.SERVER_NOT_THE_DAEMON_PRINCIPAL

        # The account is remapped to the uid the listener actually runs as.
        account["uid"] = ME
        connection = connect(profile, account_uid=account_uid)
        try:
            assert connection.expected_uid == ME
            assert connection.server_credential.uid == ME
            assert connection.verified
            # And back again, on one connection that has already succeeded.
            account["uid"] = STRANGER
            connection.http.sock = None
            with pytest.raises(SocketClientProblem):
                connection.reconnect()
            assert connection.expected_uid == ME, "a refused open must not adopt its expectation"
        finally:
            connection.close()


@requires_platforms(*OS_REAL_PLATFORMS)
def test_the_reported_expectation_follows_the_credential_that_was_checked(
    tmp_path: Path,
) -> None:
    """Article 2: what the client reports verifying is what it verified."""
    address = tmp_path / "daemon.sock"
    profile = SocketProfile(str(address), mode="system", daemon_user="sayfirst")
    with listening(address):
        connection = connect(profile, account_uid=lambda _: ME)
        try:
            first = connection.server_credential
            connection.http.sock = None
            connection.reconnect()
            assert connection.expected_uid == ME
            assert connection.server_credential.uid == ME
            assert connection.server_credential is not first
        finally:
            connection.close()


def test_a_per_user_profile_expects_this_account() -> None:
    """Rule C1: per-user is the client's own effective uid, resolved nowhere."""
    assert expected_principal_uid(SocketProfile("/run/d.sock")) == ME
