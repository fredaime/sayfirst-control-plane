# SPDX-License-Identifier: Apache-2.0
"""Standing a real system-mode daemon up as root, without poisoning the run.

`_drop_privileges` calls `setuid`, which is irreversible on purpose (rule M3).
A guard that calls it in the test process ends that process's privilege for
good: every later guard that touches a root-owned temporary directory fails,
and the run reports a hundred and seventy-nine errors with one cause. So the
daemon runs in a forked child here and the guard stays root, reads the child's
credentials from the kernel's own record, and speaks to the address over a
socket like any other client.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from sayfirst_control_plane.adapters.nss_directory import account_uid, group_id

_RUN_DIRECTORY = os.environ.get("SAYFIRST_ROOT_GUARD_RUN_DIRECTORY", "/run")
"""Where a deployment is laid out: root-owned, traversable, and not sticky."""

RUN_AS = os.environ.get("SAYFIRST_ROOT_GUARD_RUN_AS", "sayfirst-daemon")
"""The account the daemon drops to. The root container creates it."""

GROUP = os.environ.get("SAYFIRST_ROOT_GUARD_GROUP", "sayfirst-admitted")
"""The admission list. A group the daemon's own account is a member of."""

CLIENT = os.environ.get("SAYFIRST_ROOT_GUARD_CLIENT", "sayfirst-client")
"""A governed principal: in the admission group, and no writer of the policy."""

OUTSIDER = os.environ.get("SAYFIRST_ROOT_GUARD_OUTSIDER", "sayfirst-outsider")
"""An account outside the admission group, which the kernel refuses at connect."""

RECIPE = "the root container must provide it; see the recipe in docs/testing/root-container.md"


@dataclass(frozen=True)
class Account:
    name: str
    uid: int
    gid: int


def required_account(name: str) -> Account:
    """The account a guard needs, or a failure that names what is missing."""
    import pwd

    uid = account_uid(name)
    assert uid is not None, f"no account {name!r}: {RECIPE}"
    return Account(name, uid, pwd.getpwnam(name).pw_gid)


def required_group(name: str) -> int:
    gid = group_id(name)
    assert gid is not None, f"no group {name!r}: {RECIPE}"
    return gid


def policy_document(*, principal: str, scope: str = "local") -> str:
    """A format-1 policy allowing one capability to one principal, in one scope."""
    return (
        "\n".join(
            (
                "format = 1",
                "[revision]",
                'reason = "the root container\'s system-mode guards"',
                "[[rule]]",
                'id = "rule-0"',
                'capability = "example.effect"',
                f'scope = "{scope}"',
                f'principals = ["user:{principal}"]',
                'outcome = "allow"',
                'reason = "the allow rule"',
            )
        )
        + "\n"
    )


@dataclass
class Deployment:
    """What a packager laid out before the daemon started, and where it is."""

    socket_path: Path
    policy_path: Path
    evidence_root: Path
    configuration_path: Path
    run_as: Account
    admission_gid: int

    def settings_document(self) -> dict[str, object]:
        return {
            "socket": {
                "mode": "system",
                "group": GROUP,
                "run_as": self.run_as.name,
                "path": str(self.socket_path),
            },
            "identity": {},
            "policy": {"path": str(self.policy_path)},
            "evidence": {"path": str(self.evidence_root)},
        }

    def configuration_toml(self) -> str:
        """The same deployment, as the file `--config` names.

        Rendered from `settings_document` rather than written out a second
        time: article 8's protections are about the file the daemon read, so a
        guard whose file said something other than the deployment under test
        would be checking the access of the wrong words (article 2). Every
        value here is a string, which is the whole of this daemon's
        configuration grammar for these sections.
        """
        lines = ["# SPDX-License-Identifier: Apache-2.0"]
        for section, members in self.settings_document().items():
            if not members:
                continue
            lines.append(f"[{section}]")
            lines.extend(f'{name} = "{value}"' for name, value in members.items())  # type: ignore[union-attr]
        return "\n".join(lines) + "\n"

    def write_configuration(self) -> None:
        """Put the current deployment in the file, keeping its owner and mode.

        Truncated in place rather than recreated, so a case that laid the file
        out root-owned at some mode keeps that layout while the words inside it
        follow whatever the case did to the deployment afterwards.
        """
        with open(self.configuration_path, "w", encoding="utf-8") as handle:
            handle.write(self.configuration_toml())


def lay_out(
    root: Path,
    *,
    principal: str,
    packager_owns_the_store: bool,
    policy_readable_after_the_drop: bool = True,
    scope: str = "local",
    configuration_mode: int = 0o640,
) -> Deployment:
    """The deployment a packager makes, and the two ways it goes wrong.

    Rule L2a says what the packager owes: the evidence root, owned by the
    account the daemon drops to and its own group at `0700`, and a policy file
    that account can read. Each is a flag here so a guard can lay out the
    deployment that forgot one and say what the daemon did about it; a guard
    that needs a root laid out wrongly in some finer way changes the owner,
    group or mode of `evidence_root` after this returns. The policy is
    `root:<admission> 0640` when readable — the layout of the first root run —
    and `root:root 0600` when not, one layout a copy made as root can arrive
    at. Its one rule allows `example.effect` in `scope`.

    The configuration file is laid out the way `docs/deployment.md` tells an
    operator to lay it out: owned by root, with the administrator group, at
    `configuration_mode`. That one number reaches all three of article 8's
    cases, because the walk reads effective access and nothing else: `0640` is
    the protected deployment, which starts and whose admitted principals are
    served; `0660` is a configuration the administrator group can write, which
    starts and whose members therefore obtain no decision; `0666` is one a
    stranger can write, which does not start at all.
    """
    run_as = required_account(RUN_AS)
    admission = required_group(GROUP)
    run_directory = root / "run"
    run_directory.mkdir(parents=True)
    os.chmod(run_directory, 0o755)
    policy_path = root / "policy.toml"
    policy_path.write_text(policy_document(principal=principal, scope=scope), encoding="utf-8")
    if policy_readable_after_the_drop:
        os.chown(policy_path, 0, admission)
        os.chmod(policy_path, 0o640)
    else:
        os.chown(policy_path, 0, 0)
        os.chmod(policy_path, 0o600)
    evidence_root = root / "evidence"
    if packager_owns_the_store:
        evidence_root.mkdir()
        os.chown(evidence_root, run_as.uid, run_as.gid)
        os.chmod(evidence_root, 0o700)
    os.chmod(root, 0o755)
    configuration_path = root / "daemon.toml"
    configuration_path.touch()
    os.chown(configuration_path, 0, admission)
    os.chmod(configuration_path, configuration_mode)
    deployment = Deployment(
        socket_path=run_directory / "daemon.sock",
        policy_path=policy_path,
        evidence_root=evidence_root,
        configuration_path=configuration_path,
        run_as=run_as,
        admission_gid=admission,
    )
    deployment.write_configuration()
    return deployment


@contextmanager
def deployment_root() -> Iterator[Path]:
    """A root-owned, world-traversable, non-sticky place to lay a deployment out.

    Not `tmp_path`. Two things rule it out, and both were found by running
    these guards rather than by reading them. It arrives `0700` under a `0700`
    `pytest-of-root`, so a governed principal cannot traverse down to the
    address at all and a guard would read "could not connect" as "refused".
    And the system temporary directory is world-writable, which the
    per-connection check of article 8 reads as write access to an ancestor of
    the policy — so every principal but the daemon's own is refused a decision
    for a reason that has nothing to do with the case under test.

    `/run` is where the documentation puts a system-mode deployment anyway, so
    the guards run against the shape an operator would really have.
    """
    root = Path(tempfile.mkdtemp(prefix="sayfirst-guard-", dir=_RUN_DIRECTORY))
    os.chmod(root, 0o755)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _start_in_a_child(deployment: Deployment, *, umask: int | None = None) -> tuple[int, str]:
    """Assemble and start the daemon in a forked child; return its pid and first word.

    The first word is `listening`, written once `start()` returned and before
    the accept loop, or `refused: ...` with the refusal `start()` raised. The
    child drops privilege and never comes back, which is the point: a guard
    that reads `/proc/<pid>/status` reads a real dropped daemon, and the
    process doing the reading is still root. `umask` is the one the child
    starts under, for a guard about what the daemon creates under a
    permissive one; the guard's own process keeps its own.
    """
    from sayfirst_control_plane.adapters.socket_server import assemble
    from sayfirst_control_plane.cli import load_settings

    # Read from the file, by the reader the daemon's own command line uses, so
    # that the deployment under test is the one a `--config` start would have
    # and `Settings` carries the path article 8's two protections check.
    deployment.write_configuration()
    settings = load_settings(deployment.configuration_path, platform="linux")
    daemon = assemble(settings, platform="linux")
    read, written = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns to the guard
        os.close(read)
        if umask is not None:
            os.umask(umask)
        try:
            daemon.start()
            os.write(written, b"listening")
            os.close(written)
            daemon.serve_forever()
        except BaseException as error:
            with os.fdopen(written, "wb") as note:
                note.write(f"refused: {type(error).__name__}: {error}".encode())
        os._exit(0)
    os.close(written)
    with os.fdopen(read, "rb") as note:
        first = note.read().decode()
    return pid, first


@contextmanager
def daemon_in_a_child(deployment: Deployment, *, umask: int | None = None) -> Iterator[int]:
    """Start the daemon in a forked child; yield its pid while it listens."""
    pid, first = _start_in_a_child(deployment, umask=umask)
    if first != "listening":
        os.waitpid(pid, 0)
    assert first == "listening", first
    try:
        yield pid
    finally:
        os.kill(pid, 15)
        os.waitpid(pid, 0)


def refused_start(deployment: Deployment) -> str:
    """Start the daemon in a forked child and return the refusal it exited with.

    A daemon that listened instead is stopped and reported: the guard that
    asked for a refusal reads "listening" as the failure it is.
    """
    pid, first = _start_in_a_child(deployment)
    if first == "listening":
        os.kill(pid, 15)
    os.waitpid(pid, 0)
    assert first.startswith("refused: "), first
    return first.removeprefix("refused: ")


def credentials_of(pid: int) -> dict[str, object]:
    """The uid, gid and supplementary groups the kernel records for a process."""
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    read: dict[str, object] = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        if key in {"Uid", "Gid"}:
            read[key.lower()] = int(value.split()[1])  # the effective id
        elif key == "Groups":
            read["groups"] = sorted(int(item) for item in value.split())
    return read


def call(
    socket_path: Path, method: str, target: str, document: object | None = None
) -> tuple[int, dict]:
    """One request on one connection, as whatever principal this process is."""
    connection = http.client.HTTPConnection("sayfirst")
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(10)
    connection.sock.connect(str(socket_path))
    body = None if document is None else json.dumps(document)
    connection.request(
        method, target, body=body, headers={"Content-Type": "application/json"} if body else {}
    )
    response = connection.getresponse()
    parsed = json.loads(response.read() or b"{}")
    connection.close()
    return response.status, parsed


def call_as(
    account: Account, socket_path: Path, method: str, target: str, document=None, *, gid=None
):  # type: ignore[no-untyped-def]
    """The same request from a child that became `account` first.

    The credential the daemon reads is the kernel's, so the only way to ask a
    question as another principal is to really be one.

    `gid` is the group the program *runs as*, which is not the same question as
    which groups the account belongs to: the peer credential carries the
    process's own group, so a program run as its administrator group — article
    8's own phrase — is a program that set that group, and the only way to ask
    a question as one is to really set it. The account's memberships are
    established first either way, so the program is still the member it was.
    """
    read, written = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child never returns to the guard
        os.close(read)
        try:
            os.initgroups(account.name, account.gid)
            os.setgid(account.gid if gid is None else gid)
            os.setuid(account.uid)
            status, parsed = call(socket_path, method, target, document)
            answer = json.dumps({"status": status, "document": parsed})
        except BaseException as error:
            answer = json.dumps({"error": f"{type(error).__name__}: {error}"})
        with os.fdopen(written, "w") as note:
            note.write(answer)
        os._exit(0)
    os.close(written)
    with os.fdopen(read) as note:
        answer = json.loads(note.read())
    os.waitpid(pid, 0)
    return answer


def wait_for(path: Path, seconds: float = 10.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"{path} never appeared")


def entries_of(store: Path) -> list[dict]:
    """Every entry in a chain file, as stored, in the order it was appended."""
    lines = store.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line]


def wait_for_decision(store: Path, decision_ref: str, seconds: float = 10.0) -> list[dict]:
    """The chain once it holds the `effect` entry of one decision, or what it held.

    The emitter is asynchronous and bounded (article 10), so a decision served
    is a decision recorded a little later; a guard that read the file at once
    would read the daemon's timing and not its store. What is waited for is
    the decision itself — the entry whose `decision_id` is the reference the
    daemon answered with — and not a count of entries, because a `grade`
    entry arrives beside it and a count of two proved nothing about the
    decision (article 2).
    """
    deadline = time.monotonic() + seconds
    entries: list[dict] = []
    while time.monotonic() < deadline:
        if store.exists():
            entries = entries_of(store)
            if any(
                entry["kind"] == "effect" and entry["body"].get("decision_id") == decision_ref
                for entry in entries
            ):
                return entries
        time.sleep(0.05)
    return entries
