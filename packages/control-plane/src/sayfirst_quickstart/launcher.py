# SPDX-License-Identifier: Apache-2.0
"""The quickstart: a first per-user control plane, from nothing, for one account.

`sayfirst-daemon up --quickstart` is a convenience over `serve`, and only that.
What it starts is the same daemon `serve --config` starts, in its own process,
reading a policy file and a configuration file a person can open — it composes
nothing `serve` would not, it holds no second policy, and it claims no grade
the daemon does not report for itself (articles 2 and 7). Everything it adds is
on this side of the daemon: it writes the two files a first run needs when they
are not there, it starts the process detached, it waits until that process has
ANSWERED before it says « ready », and it remembers which process it started so
that `down` stops that one and no other.

**What it writes, it writes once.** The policy and the configuration are
created with an exclusive create, so a file that exists — edited, emptied, or
replaced by a link — is somebody's and is left exactly as it is. A broken edit
is then the daemon's own start refusal, said in the daemon's words, and never a
reason to put the starter back over it.

**What it stops, it has proved.** A process id is a number the system reuses,
so the record of a start carries more than one: the id, the instant the system
says that process began, and the address it serves. The instant is what proves
the id still names the same process — a verified peer credential says which
process is listening *now*, not which invocation started it, so an id the system
handed to a manually started daemon would answer that credential just as ours
would. `down` therefore signals a process only when the instant the system now
reports for the id equals the recorded one, and it sends that signal pinned to
that process (a `pidfd` where the kernel offers one), so a number reused between
the proof and the signal is never the one that receives it. An id whose recorded
instant no longer matches names a process this command did not start, and it is
left running; an id whose instant cannot be read at all is left unproved — never
signalled, and, while the id is still alive, never removed either, because a
number that cannot be checked is an unknown, not a death (article 2). No process
is ever looked up by name.

The instant a process began repeats across a reboot — a later boot can hand a
new process the same id and the same measured start — so the recorded instant is
scoped to the boot it was read on, and a record that outlived a reboot proves
nothing.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import errno
import fcntl
import json
import os
import pwd
import signal
import socket
import stat as stat_module
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Final, Literal, TextIO

from sayfirst_contract.client import Answered
from sayfirst_contract.transport.cli import render_status
from sayfirst_contract.transport.socket_client import (
    ProfileMisuse,
    SocketClientProblem,
    SocketProfile,
    connect,
)
from sayfirst_control_plane.settings import EX_CONFIG, PER_USER, Settings, StartRefused

#: The module that IS the daemon, started by name with this same interpreter.
SERVER_MODULE: Final[str] = "sayfirst_control_plane.cli"

#: Where the quickstart lives, below the home directory of the account.
DIRECTORY: Final[tuple[str, str]] = (".sayfirst", "quickstart")

POLICY_FILE: Final[str] = "policy.toml"
CONFIGURATION_FILE: Final[str] = "daemon.toml"
EVIDENCE_DIRECTORY: Final[str] = "evidence"
LOG_FILE: Final[str] = "daemon.log"
RECORD_FILE: Final[str] = "daemon.run.json"
LOCK_FILE: Final[str] = "daemon.lock"

PRIVATE_DIRECTORY: Final[int] = 0o700
PRIVATE_FILE: Final[int] = 0o600


class QuickstartRefused(Exception):
    """The quickstart will not go on, and the sentence says what a person can do."""


@dataclass(frozen=True)
class Layout:
    """Every name the quickstart uses, all below one directory."""

    root: Path
    policy: Path
    configuration: Path
    evidence: Path
    log: Path
    record: Path
    lock: Path


def layout(home: str) -> Layout:
    """The quickstart's names for one home directory. Nothing is created."""
    root = Path(home).joinpath(*DIRECTORY)
    return Layout(
        root=root,
        policy=root / POLICY_FILE,
        configuration=root / CONFIGURATION_FILE,
        evidence=root / EVIDENCE_DIRECTORY,
        log=root / LOG_FILE,
        record=root / RECORD_FILE,
        lock=root / LOCK_FILE,
    )


def _quoted(value: str) -> str:
    """One TOML basic string, so that a name with a quote in it reads back as itself."""
    escaped = "".join(
        {"\\": "\\\\", '"': '\\"'}.get(character)
        or (f"\\u{ord(character):04x}" if ord(character) < 0x20 or ord(character) == 0x7F else "")
        or character
        for character in value
    )
    return f'"{escaped}"'


def starter_policy(account: str) -> str:
    """The policy a first run starts from: three outcomes, readable, and editable.

    It names the account it was written for, because a rule is for the
    principals it names and the format has no way to say « whoever runs this »
    — the daemon establishes who is asking from the socket, never from the file
    (article 6). The name is read from the operating system when the file is
    written and appears nowhere in this source.

    The capabilities are the three kinds of effect the project's convenience
    packs ask about, chosen so that every outcome can be seen without an edit:
    one allowed, one held for a person, one not named at all.
    """
    principal = _quoted(f"user:{account}")
    return f"""\
# SayFirst quickstart policy. This file is yours to edit.
#
# `sayfirst-daemon up --quickstart` wrote it once, and it is never overwritten
# by that command afterwards. Delete it and run the command again to get this
# starter back.
#
# The control plane reads this file when it decides: save an edit and run your
# program again, nothing needs restarting. While the file does not read (a
# typing mistake, say) no question is answered at all: the answer is the
# problem policy_unavailable, which is not permission, so nothing runs on the
# strength of an older version.
#
# A rule answers ONE kind of effect (its capability), in ONE scope, for the
# accounts it names, with one of three outcomes:
#
#   "allow"    the effect runs
#   "deny"     the effect does not run
#   "suspend"  the effect does not run now. The program is told so at once
#              (the boundary raises Suspended, and a program that does not
#              catch it ends there), and a person approves or rejects the
#              wait:
#                sayfirst approvals show    --approval REF --scope local
#                sayfirst approvals approve --approval REF --scope local
#              Once it is approved, the same question asked again (run the
#              program again) is allowed, once; once rejected, it is denied.
#
# An effect no rule names is denied, and the reason says so: policy_absent.
# Where several rules apply to one question, deny wins over suspend, and
# suspend wins over allow.
#
# A rule is for the accounts it names and nobody else. This file names the
# account that ran the quickstart.

format = 1

[revision]
reason = "the starter policy of the quickstart"

# Starting a process: what `sayfirst instrument run --pack subprocess` asks
# about. Change "allow" to "deny" or to "suspend", save, and run again.
[[rule]]
id = "local-processes-run"
capability = "process.spawn"
scope = "local"
principals = [{principal}]
outcome = "allow"
reason = "starting a local process is allowed on this machine"

# Opening a URL: what `--pack http-client` asks about, for every URL that
# urllib.request.urlopen opens - http and https requests, and file: and
# data: reads as well (the URL is in the digest the question carries). A
# person has ten minutes to answer before the wait ends by itself.
#
# review_deadline_seconds belongs to a "suspend" rule and to no other. To
# make this rule "allow" or "deny", delete that line too: left in, it makes
# the whole file invalid, so every question is answered policy_unavailable,
# and a daemon started on the file refuses to start
# (policy_unavailable_at_start).
[[rule]]
id = "requests-wait-for-a-person"
capability = "net.egress"
scope = "local"
principals = [{principal}]
outcome = "suspend"
reason = "opening a URL waits for a person on this machine"
review_deadline_seconds = 600

# Opening a database (`--pack database`, capability database.open) is left
# unnamed on purpose, so it is denied with policy_absent. Add a rule for it to
# change that.
"""


def starter_configuration(names: Layout) -> str:
    """The configuration of a per-user daemon that reads the two names above.

    No address: a per-user daemon given none serves at the default one, which
    is the address a client given none looks at, so neither is told. The two
    paths are absolute because the daemon reads no other kind, and they are
    resolved when the file is written, from the home directory the operating
    system reports.
    """
    return f"""\
# SayFirst quickstart configuration, written once by
# `sayfirst-daemon up --quickstart` and never overwritten by it.
#
# Per-user mode: one account, and the socket is that account's alone. No
# socket path is named, so the daemon serves at the per-user default address:
# $XDG_RUNTIME_DIR/sayfirst/daemon.sock where that directory exists, and
# ~/.sayfirst/run/daemon.sock otherwise. A client given no --socket looks there.

[socket]
mode = "per_user"

[policy]
path = {_quoted(str(names.policy))}

[evidence]
path = {_quoted(str(names.evidence))}
"""


def prepare(names: Layout, *, account: str) -> list[Path]:
    """Create what a first run needs and is not there; answer with what was written.

    Directories arrive at `0700` and files at `0600` whatever the umask, and
    nothing that exists is changed: not a file, and not a directory's
    permissions either — a quickstart directory other accounts can reach is
    refused with the command that repairs it, because loosening it was
    somebody's act and this command does not know better.
    """
    _private_directory(names.root.parent, create_only=True)
    _private_directory(names.root, create_only=False)
    _private_directory(names.evidence, create_only=False)
    written = []
    for path, content in (
        (names.policy, starter_policy(account)),
        (names.configuration, starter_configuration(names)),
    ):
        if _write_once(path, content):
            written.append(path)
    return written


def _private_directory(path: Path, *, create_only: bool) -> None:
    """A directory of this account's alone: created so, or found so, or refused.

    `create_only` is for the level above the quickstart's own, which may be a
    directory a person already keeps other things in: it is created private
    when it is missing and otherwise left to the daemon's own start checks,
    which judge every level of a name (article 8).
    """
    try:
        os.mkdir(path, PRIVATE_DIRECTORY)
    except FileExistsError:
        if create_only:
            return
    else:
        # `mkdir` takes the umask off its mode; the mode is set again so that a
        # stricter umask cannot leave a directory this account cannot enter. The
        # mode is set on the directory this call just created, reached through an
        # `O_NOFOLLOW` handle to it, not by its name: a name swapped for a link
        # between the create and here is refused rather than followed to whatever
        # it points at.
        opened = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(opened, PRIVATE_DIRECTORY)
        finally:
            os.close(opened)
        return
    _judge_private_directory(path)


def _judge_private_directory(path: Path) -> None:
    """An existing directory, judged by its own entry, no link followed: this account's, private."""
    found = os.lstat(path)
    if not stat_module.S_ISDIR(found.st_mode):
        raise QuickstartRefused(f"{path} is not a directory of its own; move it aside")
    if found.st_uid != os.geteuid():
        raise QuickstartRefused(f"{path} belongs to another account; move it aside")
    if stat_module.S_IMODE(found.st_mode) & 0o077:
        raise QuickstartRefused(
            f"{path} can be reached by other accounts "
            f"({stat_module.S_IMODE(found.st_mode):04o}); make it private with: chmod 700 {path}"
        )


def _write_once(path: Path, content: str) -> bool:
    """Write a file that is not there, and say whether this call wrote it.

    An exclusive create, so the check and the write are one act: a name that is
    taken — by a file, a directory, or a link pointing at nothing — is left
    alone, and nothing can be put in the way between looking and writing.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE)
    except FileExistsError:
        return False
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), PRIVATE_FILE)
        stream.write(content)
    return True


# -- the record of a start ---------------------------------------------------------


@dataclass(frozen=True)
class Started:
    """Which process a start began, when the system says it began, and where it serves.

    The policy and evidence paths are the ones the daemon was started on. The
    daemon reads its configuration once, so a `daemon.toml` edited afterwards
    names paths the running daemon does not use — a report of what is running
    reads these, never the file.
    """

    pid: int
    began: str | None
    socket: str
    policy: str | None = None
    evidence: str | None = None


#: macOS's process table, read through `sysctl`: the record of one process, its
#: state code for a zombie, and where in the record the three fields this reads
#: sit. `struct kinfo_proc` opens with `struct extern_proc`, whose first member is
#: the start time (`struct timeval`), followed by two pointers, the flags, the
#: state and — after alignment — the process id.
_CTL_KERN: Final[int] = 1
_KERN_PROC: Final[int] = 14
_KERN_PROC_PID: Final[int] = 1
_KINFO_PROC_SIZE: Final[int] = 648
_DARWIN_ZOMBIE: Final[int] = 5
_DARWIN_STATE_AT: Final[int] = 36
_DARWIN_PID_AT: Final[int] = 40


@cache
def _darwin_libc() -> ctypes.CDLL:
    library = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    library.sysctl.argtypes = [
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.sysctl.restype = ctypes.c_int
    library.sysctlbyname.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.sysctlbyname.restype = ctypes.c_int
    return library


def _darwin_process_state(pid: int) -> tuple[str, str] | None:
    """macOS's own record of a process: whether it is a zombie, and when it began.

    The record carries the process id as well, and it is compared with the one
    asked for: a record this reads wrongly is then no answer rather than a
    wrong one, and « no answer » is what every caller already treats as a
    process this command cannot prove (article 2).
    """
    try:
        names = (ctypes.c_int * 4)(_CTL_KERN, _KERN_PROC, _KERN_PROC_PID, pid)
        record = ctypes.create_string_buffer(_KINFO_PROC_SIZE)
        size = ctypes.c_size_t(_KINFO_PROC_SIZE)
        if _darwin_libc().sysctl(names, 4, record, ctypes.byref(size), None, 0) != 0:
            return None
    except (OSError, AttributeError, TypeError):
        return None
    if size.value < _DARWIN_PID_AT + 4:
        return None  # nothing holds that id: the kernel filled no record
    (recorded_pid,) = struct.unpack_from("=i", record.raw, _DARWIN_PID_AT)
    if recorded_pid != pid:
        return None
    seconds, microseconds = struct.unpack_from("=qi", record.raw, 0)
    state = "Z" if record.raw[_DARWIN_STATE_AT] == _DARWIN_ZOMBIE else "S"
    return state, f"{seconds}.{microseconds:06d}"


def _process_state(pid: int) -> tuple[str, str] | None:
    """The system's own record of a process: its state letter and when it began.

    Read from `/proc/<pid>/stat` on Linux, where the instant is field 22,
    measured from boot; from the process table through `sysctl` on macOS, where
    it is the start time the kernel keeps. Either way it never changes for the
    life of a process, which is what makes it a proof that an id still names the
    same process. Only « Z » (a zombie) is read from the state letter. A
    platform with neither answers `None`, and a caller that gets `None` has
    proved nothing.
    """
    if sys.platform == "darwin":
        return _darwin_process_state(pid)
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # The second field is the command in parentheses and may itself hold spaces
    # and parentheses; everything after the LAST one is positional.
    fields = text.rpartition(")")[2].split()
    return (fields[0], fields[19]) if len(fields) > 19 else None


def _boot_identity() -> str | None:
    """A token that names the current boot, or `None` where the platform offers none.

    The start instant a process carries is measured from boot, so it repeats
    across reboots. Pairing it with the boot's own identity makes a recorded
    instant belong to one boot: a record that survived a reboot then reads as a
    different process, which is what it is. Linux publishes the boot's id under
    `/proc`; macOS gives each boot session a UUID of its own.
    """
    if sys.platform == "darwin":
        try:
            value = ctypes.create_string_buffer(64)
            size = ctypes.c_size_t(64)
            if _darwin_libc().sysctlbyname(
                b"kern.bootsessionuuid", value, ctypes.byref(size), None, 0
            ):
                return None
        except (OSError, AttributeError, TypeError):
            return None
        return value.value.decode("ascii", "replace").strip() or None
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return None


def process_began(pid: int) -> str | None:
    """The instant the system says a process began, as an opaque token, or `None`.

    The token is the process's start instant (field 22 of `/proc/<pid>/stat`,
    measured since boot and unchanging for the process's life) scoped to the boot
    it was read on, so the same id and instant on a later boot never read as the
    same process. Where the platform names no boot the instant stands alone, as
    it did before; where it keeps no record of a process's start at all, the
    answer is `None` and a caller has proved nothing.
    """
    state = _process_state(pid)
    if state is None:
        return None
    boot = _boot_identity()
    return state[1] if boot is None else f"{boot}:{state[1]}"


def write_record(names: Layout, started: Started) -> None:
    """Record a start, whole or not at all: written beside the name, then renamed."""
    temporary = names.record.with_name(f"{names.record.name}.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), PRIVATE_FILE)
        json.dump(
            {
                "pid": started.pid,
                "began": started.began,
                "socket": started.socket,
                "policy": started.policy,
                "evidence": started.evidence,
            },
            stream,
        )
        stream.write("\n")
    os.replace(temporary, names.record)


def read_record(names: Layout) -> Started | None:
    """The recorded start, or `None` for a record that is absent or does not read."""
    try:
        descriptor = os.open(names.record, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        found = os.fstat(descriptor)
        if not stat_module.S_ISREG(found.st_mode) or found.st_uid != os.geteuid():
            # Not a file of this account's: it proves nothing about a start of
            # this account's, so it is not read as one. (Who else can write it
            # is the directory's question, which `down` asks before this.)
            return None
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = None
            document = json.loads(stream.read())
    except (OSError, ValueError, RecursionError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(document, dict):
        return None
    pid, began, address = document.get("pid"), document.get("began"), document.get("socket")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 2 or not isinstance(address, str):
        return None
    policy, evidence = document.get("policy"), document.get("evidence")
    return Started(
        pid,
        began if isinstance(began, str) else None,
        address,
        policy if isinstance(policy, str) else None,
        evidence if isinstance(evidence, str) else None,
    )


def forget_record(names: Layout) -> None:
    with contextlib.suppress(FileNotFoundError):
        names.record.unlink()


@contextlib.contextmanager
def _exclusive(names: Layout):
    """Hold a lifecycle lock so no two `up`/`down` race the one shared record.

    Two `up` commands that both find no record would each start a daemon and the
    second would write over the record of the first, whom `down` could then never
    stop. The read of the record, the start, and the write of the new record are
    one critical section, ordered here by an advisory lock on a file of the
    quickstart's own. It is advisory, so the daemon — which never takes it — is
    never blocked by it, and the descriptor is this process's alone (closed on
    exec), so a started daemon does not inherit and hold it.

    A lock that is a link is refused by name, before anything is locked: the
    open does not follow it, so nothing it points at is created or changed.
    """
    try:
        descriptor = os.open(names.lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, PRIVATE_FILE)
    except OSError as error:
        if error.errno != errno.ELOOP:
            raise
        raise QuickstartRefused(f"{names.lock} is a link; move it aside") from error
    try:
        os.fchmod(descriptor, PRIVATE_FILE)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


# -- asking the daemon -------------------------------------------------------------


#: How long a single status probe waits — to connect, to read the peer
#: credential, and to read the answer — before it counts as no answer. A probe
#: is asked again and again while `up` waits, so this bounds each attempt, not
#: the wait: a listener that accepts a connection and then never answers must not
#: hold a probe open past this, or `up` and `down` never reach their own
#: deadlines.
PROBE_SECONDS: Final[float] = 5.0


@dataclass(frozen=True)
class Listener:
    """A daemon that ANSWERED at an address: who the kernel says it is, and what it said."""

    pid: int | None
    status: Mapping[str, object]


def _probe_socket() -> socket.socket:
    """A stream whose every blocking step is bounded, so a silent listener cannot hang a probe."""
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(PROBE_SECONDS)
    return stream


def answering(address: str) -> Listener | None:
    """Ask the daemon at an address for its status, through the published transport.

    `None` is every way of not getting an answer: nobody there, somebody there
    who is not this account's daemon (the transport refuses it before a byte is
    sent, article 6), a reply that does not read, or a listener that accepts the
    connection and then does not answer within `PROBE_SECONDS`. « Ready » is only
    ever said about a `Listener`, so it is only ever said about a daemon that
    answered.
    """
    try:
        connection = connect(SocketProfile(address), socket_factory=_probe_socket)
    except (SocketClientProblem, ProfileMisuse, OSError):
        return None
    with contextlib.closing(connection):
        try:
            status = connection.read_status()
            if not isinstance(status, Answered):
                return None
            return Listener(connection.server_credential.pid, status.value.to_document())
        except Exception:
            return None


def _running(pid: int) -> bool:
    """Whether a process is still running: present, and not merely awaiting its parent."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    state = _process_state(pid)
    return state is None or state[0] != "Z"


Identity = Literal["ours", "gone", "unknown"]


def _identity(record: Started) -> Identity:
    """Whether the recorded id still names the process that start began.

    Three answers, because the evidence has three states (article 2):

    - « gone »: nothing runs under the id (a zombie counts as nothing: it has
      exited and keeps only its start instant), or something else does — it
      began at another instant, or at the same instant on another boot.
    - « ours »: the id runs, and began at exactly the recorded instant on the
      recorded boot.
    - « unknown »: the id runs and the question cannot be settled — the record
      carries no instant, the instant cannot be read here, or the record was
      written without the boot and shows the same instant, so which boot it
      belongs to is not said anywhere.

    The recorded instant is read in the format it was written in: a record from
    before the boot was part of the token carries the instant alone.
    """
    if not _running(record.pid):
        return "gone"
    now = process_began(record.pid)
    if record.began is None or now is None:
        return "unknown"
    if record.began == now:
        return "ours"
    recorded_boot, _, recorded_instant = record.began.rpartition(":")
    boot_now, _, instant_now = now.rpartition(":")
    if recorded_instant != instant_now:
        return "gone"
    if recorded_boot and boot_now:
        return "gone"
    return "unknown"


def _earlier_daemon_running(record: Started) -> bool:
    """Whether the process an earlier `up` recorded is proved to be still running.

    True only for « ours »: the id runs, is not a zombie, and began at the
    recorded instant on the recorded boot. A process that has exited but not
    been reaped keeps its start instant, so reading only the instant would call
    a daemon that is already gone « still running » — for good, on a host whose
    init does not reap what a crash orphaned.
    """
    return _identity(record) == "ours"


def _request_stop(record: Started) -> None:
    """Send one SIGTERM to the recorded process, and to no other.

    The id is pinned first, by a `pidfd` where the kernel offers one, and the
    start instant is checked once more against the pinned id: a number reused
    before the pin yields a handle to the new process whose instant differs, and
    nothing is signalled; a number reused after the pin cannot be reached at all,
    because the handle names the original and never the newcomer. Where no
    `pidfd` is available the numeric id is used, which is the platform's own
    limit, and the same instant check guards it.
    """
    opener = getattr(os, "pidfd_open", None)
    send = getattr(signal, "pidfd_send_signal", None)
    if opener is not None and send is not None:
        try:
            handle = opener(record.pid)
        except ProcessLookupError:
            return  # gone between the proof and here
        except OSError:
            handle = None
        if handle is not None:
            try:
                if record.began is not None and process_began(record.pid) == record.began:
                    with contextlib.suppress(ProcessLookupError, OSError):
                        send(handle, signal.SIGTERM)
            finally:
                os.close(handle)
            return
    with contextlib.suppress(ProcessLookupError):
        if record.began is not None and process_began(record.pid) == record.began:
            os.kill(record.pid, signal.SIGTERM)


def _wait_stopped(child: subprocess.Popen, seconds: float) -> bool:
    """Wait up to `seconds` for a child to exit; say whether it did."""
    try:
        child.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


def _forget_if_ours(names: Layout, pid: int) -> None:
    """Remove the record, but only while it still names the process this call started.

    The readiness wait runs outside the lifecycle lock; this re-takes it so that a
    record another command wrote in the meantime is never removed by mistake.
    """
    with _exclusive(names):
        current = read_record(names)
        if current is not None and current.pid == pid:
            forget_record(names)


# -- up ----------------------------------------------------------------------------

#: How long a started daemon has to answer before `up` gives up on it.
READY_SECONDS: Final[float] = 20.0

#: How long a daemon asked to stop has to be gone before `down` says it is not.
STOP_SECONDS: Final[float] = 20.0

#: The exit status of a start or a stop that did not happen for a reason other
#: than the daemon's own refusal, which keeps its own status.
EXIT_NOT_DONE: Final[int] = 1


def up(
    *,
    home: str,
    read_settings_from: Callable[[Path], Settings],
    out: TextIO,
    err: TextIO,
) -> int:
    """Write what is missing, start the real daemon detached, and wait for its answer."""
    names = layout(home)
    if os.geteuid() == 0:
        # Before anything is created. Run through a privilege tool this would
        # leave root's files in somebody's home directory, and a per-user daemon
        # of root's is not what anybody asking for a quickstart wants.
        print(
            "quickstart: this is one ordinary account's first run, and it is being run as "
            "root. Run it as yourself, without a privilege tool. A daemon that serves "
            "several accounts is system mode, which `sayfirst-daemon serve --config` starts",
            file=err,
        )
        return EX_CONFIG
    try:
        written = prepare(names, account=pwd.getpwuid(os.geteuid()).pw_name)
        settings = read_settings_from(names.configuration)
    except (QuickstartRefused, OSError) as refusal:
        print(f"quickstart: {refusal}", file=err)
        return EX_CONFIG
    except StartRefused as refusal:
        print(f"{refusal.reason}: {refusal.detail}", file=err)
        return EX_CONFIG
    if settings.mode != PER_USER:
        print(
            f"quickstart: {names.configuration} configures {settings.mode} mode, and the "
            f"quickstart is per-user; start that daemon with `sayfirst-daemon serve --config`",
            file=err,
        )
        return EX_CONFIG

    # The read of the record, the decision, the start, and the write of the new
    # record are one critical section: two `up`s that both saw no record would
    # both start a daemon, and the second would write over the first's only
    # record. The readiness wait is left outside the lock, so a start does not
    # hold it for the whole of a slow answer.
    with contextlib.ExitStack() as held:
        try:
            held.enter_context(_exclusive(names))
        except QuickstartRefused as refusal:
            print(f"quickstart: {refusal}", file=err)
            return EX_CONFIG
        record = read_record(names)
        identity = _identity(record) if record is not None else "gone"
        if record is not None and identity == "unknown":
            # A process lives under the recorded id and this command cannot tell
            # whether it is the daemon it started. `down` will not stop it for
            # that reason; starting another here would write over the only
            # record of it. Nothing is started and the record stays (article 2).
            print(
                f"quickstart: a process is alive at pid {record.pid}, the id this command "
                f"recorded for its daemon, and this command cannot prove it is that daemon "
                f"(its start instant cannot be read or compared here). Nothing was started "
                f"and the record was kept. If it is not the daemon, remove {names.record} "
                f"by hand and run this again.",
                file=err,
            )
            return EXIT_NOT_DONE
        # The address the recorded daemon was started on, which is where it
        # answers: the configuration may name another one since.
        probed = record.socket if record is not None else settings.socket_path
        listener = answering(probed)
        if (
            record is not None
            and identity == "ours"
            and listener is not None
            and listener.pid == record.pid
        ):
            # Answering at the address it was started on, with our id, begun at
            # the recorded instant: proved to be the very daemon this command
            # started. What it reads is what it was started on.
            _report(
                "already running", names, settings, listener, record.pid, [], out, started_on=record
            )
            return 0
        if record is not None and identity == "ours":
            # The process an earlier `up` started is still there — begun when the
            # record says, and not a zombie — and it is not the one answering.
            # Starting another would write over the only record of it, and `down`
            # could then never stop it; so nothing is started and the record is
            # left as it is.
            print(
                f"quickstart: the daemon this command started earlier (pid {record.pid}) is "
                f"still running and is not answering at {record.socket}. Nothing was started. "
                f"`sayfirst-daemon down` stops it; its log is {names.log}",
                file=err,
            )
            return EXIT_NOT_DONE

        log = os.open(names.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE)
        try:
            os.fchmod(log, PRIVATE_FILE)
            said_before = os.fstat(log).st_size
            # The same interpreter and the same installed package, by module name:
            # never a `sayfirst-daemon` looked up on a search path, which could be
            # another installation's. `-P` keeps the working directory off its path.
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-P",
                    "-m",
                    SERVER_MODULE,
                    "serve",
                    "--config",
                    str(names.configuration),
                ],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
                cwd="/",
            )
        finally:
            os.close(log)
        try:
            write_record(
                names,
                Started(
                    child.pid,
                    process_began(child.pid),
                    settings.socket_path,
                    settings.policy_path,
                    settings.evidence_root,
                ),
            )
        except OSError as failure:
            # The daemon started but its record did not, so `down` could not find
            # it. It is stopped here rather than left to serve unmanageable.
            child.terminate()
            stopped = _wait_stopped(child, STOP_SECONDS)
            here = (
                "it was stopped, so nothing runs unmanaged"
                if stopped
                else (
                    f"it did not stop when asked and is still running as pid {child.pid}, "
                    f"with no record `sayfirst-daemon down` can use: stop it by that pid"
                )
            )
            print(
                f"quickstart: the daemon was started but its record could not be written "
                f"({failure}); {here}",
                file=err,
            )
            return EXIT_NOT_DONE

    deadline = time.monotonic() + READY_SECONDS
    while True:
        status = child.poll()
        if status is not None:
            _forget_if_ours(names, child.pid)
            said = _said_since(names, said_before)
            err.write(said)
            if "socket_in_use" in said:
                print(
                    f"quickstart: something this command did not start is at "
                    f"{settings.socket_path}; `sayfirst-daemon down` stops only what `up` started",
                    file=err,
                )
            return status if status > 0 else EXIT_NOT_DONE
        listener = answering(settings.socket_path)
        if listener is not None and (
            listener.pid == child.pid
            or (listener.pid is None and "serving " in _said_since(names, said_before))
        ):
            break
        if time.monotonic() > deadline:
            child.terminate()
            stopped = _wait_stopped(child, STOP_SECONDS)
            err.write(_said_since(names, said_before))
            if stopped:
                _forget_if_ours(names, child.pid)
                print(
                    f"quickstart: the daemon did not answer at {settings.socket_path} within "
                    f"{READY_SECONDS:g} seconds, so it was stopped and nothing is claimed ready",
                    file=err,
                )
            else:
                # It did not answer AND did not stop when asked: it is still
                # running. The record is kept so `down` can stop it, and nothing
                # is claimed either ready or stopped (article 2).
                print(
                    f"quickstart: the daemon did not answer at {settings.socket_path} within "
                    f"{READY_SECONDS:g} seconds and did not stop when asked; it is still running "
                    f"as pid {child.pid}. `sayfirst-daemon down` stops it; its log is {names.log}",
                    file=err,
                )
            return EXIT_NOT_DONE
        time.sleep(0.05)
    _report("ready", names, settings, listener, child.pid, written, out)
    return 0


def _said_since(names: Layout, offset: int) -> str:
    """What the daemon wrote to its log since this start began."""
    try:
        with open(names.log, "rb") as stream:
            stream.seek(offset)
            return stream.read().decode(errors="replace")
    except OSError:
        return ""


def _report(
    state: str,
    names: Layout,
    settings: Settings,
    listener: Listener,
    pid: int,
    written: list[Path],
    out: TextIO,
    *,
    started_on: Started | None = None,
) -> None:
    """What is running and where, in the daemon's own words wherever it has any.

    The address and the two paths are the ones the daemon was started on. For a
    start this command just made, that is the configuration it read; for a
    daemon already running, it is what the record kept at its start — the
    daemon reads its configuration once, so a file edited since names paths it
    does not use, and printing those as its own would send a person to edit a
    policy that governs nothing. Where the file now says otherwise, a line says
    so. The grade and the lines after it are `status` as the daemon just
    answered it, rendered by the contract's own renderer: this command has no
    sentence of its own about how much the evidence can be trusted (article 7).
    """
    socket_path = started_on.socket if started_on is not None else settings.socket_path
    policy = (started_on.policy if started_on is not None else None) or settings.policy_path
    evidence = (started_on.evidence if started_on is not None else None) or settings.evidence_root
    print(f"SayFirst Control Plane {state}", file=out)
    print(f"mode: {settings.mode}", file=out)
    print(f"socket: {socket_path}", file=out)
    print(f"policy: {policy}", file=out)
    print(f"evidence: {evidence}", file=out)
    print(render_status(listener.status), file=out)
    print(f"log: {names.log}", file=out)
    print(f"pid: {pid}", file=out)
    for path in written:
        print(f"wrote: {path}", file=out)
    if started_on is not None:
        for what, running, configured in (
            ("socket", socket_path, settings.socket_path),
            ("policy", policy, settings.policy_path),
            ("evidence", evidence, settings.evidence_root),
        ):
            if running != configured:
                print(
                    f"note: {names.configuration} now names {what} {configured}; the running "
                    f"daemon reads the {what} above until it is restarted "
                    f"(sayfirst-daemon down, then up)",
                    file=out,
                )
    print("stop: sayfirst-daemon down", file=out)


# -- down --------------------------------------------------------------------------


def down(
    *,
    home: str,
    read_settings_from: Callable[[Path], Settings],
    out: TextIO,
    err: TextIO,
) -> int:
    """Stop the daemon `up` started, once it is proved to be that one, and no other."""
    names = layout(home)
    if os.geteuid() == 0:
        print(
            "quickstart: `down` stops one ordinary account's quickstart daemon, and it is "
            "being run as root. Run it as the account that ran `up`, without a privilege tool",
            file=err,
        )
        return EX_CONFIG
    if not os.path.lexists(names.root):
        # Nothing was ever started under this home: there is no quickstart
        # directory to hold a record or a lock, and nothing to stop.
        print("SayFirst Control Plane not running", file=out)
        return 0
    try:
        _judge_private_directory(names.root)
    except QuickstartRefused as refusal:
        print(f"quickstart: {refusal}; nothing was signalled", file=err)
        return EX_CONFIG
    with contextlib.ExitStack() as held:
        try:
            held.enter_context(_exclusive(names))
        except QuickstartRefused as refusal:
            print(f"quickstart: {refusal}; nothing was signalled", file=err)
            return EX_CONFIG
        record = read_record(names)
        if record is None:
            address = _configured_address(names, read_settings_from)
            if address is not None and answering(address) is not None:
                print(
                    f"quickstart: a control plane is answering at {address}, and this command "
                    f"did not start it (there is no record of a start), so it is left running",
                    file=err,
                )
                return EXIT_NOT_DONE
            print("SayFirst Control Plane not running", file=out)
            return 0

        listener = answering(record.socket)
        # A verified peer credential says which process is listening now, not
        # which invocation started it, so the recorded start instant — on the
        # boot it was read on — and it alone proves the id still names the
        # daemon this command started.
        identity = _identity(record)
        if identity == "unknown":
            # The id is alive, and whether it is the daemon this command started
            # cannot be settled here: the record carries no instant, the instant
            # cannot be read, or the record does not say which boot its instant
            # belongs to. It is neither signalled (it might be another process)
            # nor forgotten (it might be ours), and the uncertainty is reported
            # rather than resolved either way (article 2).
            print(
                f"quickstart: a process is alive at pid {record.pid} and this command cannot "
                f"prove it is the daemon it started (its start instant cannot be read or "
                f"compared here). Nothing was signalled and the record was kept. If it is not "
                f"the daemon, remove {names.record} by hand.",
                file=err,
            )
            return EXIT_NOT_DONE
        if identity == "gone":
            forget_record(names)
            if listener is not None:
                print(
                    f"quickstart: the control plane answering at {record.socket} is not the "
                    f"process this command started (pid {record.pid}, which is gone); this "
                    f"command did not start it, so it is left running. The stale record was "
                    f"removed.",
                    file=err,
                )
                return EXIT_NOT_DONE
            print("SayFirst Control Plane not running", file=out)
            print(
                f"a stale record of pid {record.pid} was removed; no signal was sent to anything",
                file=out,
            )
            return 0

        _request_stop(record)
        deadline = time.monotonic() + STOP_SECONDS
        while _running(record.pid):
            if time.monotonic() > deadline:
                print(
                    f"quickstart: pid {record.pid} was asked to stop and has not ended after "
                    f"{STOP_SECONDS:g} seconds. It was sent one SIGTERM and nothing stronger: a "
                    f"daemon killed outright leaves its evidence epoch open. Its log is "
                    f"{names.log}",
                    file=err,
                )
                return EXIT_NOT_DONE
            time.sleep(0.05)
        forget_record(names)
        print(f"SayFirst Control Plane stopped (pid {record.pid})", file=out)
        print(f"policy and evidence are kept under {names.root}", file=out)
        return 0


def _configured_address(
    names: Layout, read_settings_from: Callable[[Path], Settings]
) -> str | None:
    """Where the quickstart's daemon would serve, or `None` when nothing says."""
    if not names.configuration.is_file():
        return None
    try:
        return read_settings_from(names.configuration).socket_path
    except (StartRefused, OSError):
        return None
