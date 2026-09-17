# SPDX-License-Identifier: Apache-2.0
"""The one place this daemon listens, and everything it does before it does.

Article 6: a Unix domain socket, and only there. There is no second listener
for tooling, no loopback exception and no way to ask for one — this module
constructs exactly one socket, of one family, and the whole served surface is
HTTP/1.1 over it.

The order of what happens before `listen()` is the point of most of this
file: the directory is checked, the mask is narrowed so the file is never
briefly wider than its final permissions, the ownership is set, and the
privileges are dropped — and only then does the daemon listen, so that the
credential a connecting client reads is the daemon's running principal.
"""

from __future__ import annotations

import errno
import logging
import os
import socket
import stat as stat_module
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Any, Final
from weakref import WeakKeyDictionary

from sayfirst_contract.transport.peer import (
    PeerCredential,
    PeerCredentialUnavailable,
    PeerIdentity,
    PeerIdentityUnsupported,
    select_peer_identity,
)
from sayfirst_contract.whoami import Delegation, Principal

from ..domain import evidence as evidence_records
from ..domain.admission import admit, is_unmapped
from ..domain.connection import REFUSED, ConnectionIdentity
from ..domain.directory_protection import DirectoryFacts, directory_protection
from ..domain.evidence import LOCAL_SCOPE, RecordCollector
from ..domain.foreign import ForeignValueRefused, core_owned_instant
from ..domain.principal import (
    build_principal,
    differs_beyond_establishment,
    kind_for,
    resolve_identity,
)
from ..ports.account_directory import (
    Account,
    AccountDirectory,
    account_of,
    group_ids_of,
    group_name_of,
)
from ..ports.clock import Clock, SystemClock
from ..ports.peer_identity import credential_of
from ..settings import (
    PER_USER,
    SYSTEM,
    Settings,
    StartRefused,
    directory_mode,
    final_file_mode,
    umask_for,
)

LOG: Final[logging.Logger] = logging.getLogger("sayfirst_control_plane.daemon")
"""The one logger of the server package; see `http_surface.LOG`."""

_ACL_ATTRIBUTE: Final[str] = "system.posix_acl_access"
_NO_SUCH_ATTRIBUTE: Final[frozenset[int]] = frozenset(
    {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}
)


@contextmanager
def _narrowed_umask(mask: int):  # type: ignore[no-untyped-def]
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


@contextmanager
def _refusing(reason: str, doing: str):  # type: ignore[no-untyped-def]
    """Name what the host refused, so a start that fails says so and exits 78.

    Every call the start sequence makes can be refused by the operating
    system, and an `OSError` that reaches `main()` is a traceback and exit 1 —
    which `docs/deployment.md` does not publish, which a supervisor keyed on
    `EX_CONFIG` reads as an ordinary crash, and which tells the operator
    nothing about what to fix. Each step therefore names the refusal it can
    produce, and the detail carries what the kernel actually said (article 2).
    """
    try:
        yield
    except OSError as error:
        raise StartRefused(reason, f"{doing}: {error}") from error


def read_overflow_ids(platform: str, root: Path = Path("/")) -> tuple[int | None, int | None]:
    """The ids the kernel reports for an unmapped peer, read once at start.

    A daemon that could not read them could not tell an identity from a
    non-identity, so it does not start (rule L8). macOS has no user
    namespaces and no such ids; the rule is vacuous there.
    """
    if platform != "linux":
        return None, None
    values = []
    for name in ("overflowuid", "overflowgid"):
        try:
            values.append(int((root / "proc/sys/kernel" / name).read_text().strip()))
        except (OSError, ValueError) as error:
            raise StartRefused("overflow_id_unreadable", f"{name}: {error}") from error
    return values[0], values[1]


def account_kind_notes(
    account_kinds: Mapping[str, str], *, lookup: Callable[[str], int | None]
) -> list[str]:
    """One line per configured account kind, saying which name the host knows.

    Rule K3: "An account name absent from the directory at start is logged,
    not refused." The mapping changes the recorded kind and the reference and
    nothing in admission or policy, so a name the host does not have yet costs
    a line in the start log and no more — but it costs that line, because a
    mapping that will never apply is a configuration the operator believes in
    and the daemon does not (article 2).
    """
    notes: list[str] = []
    for name in account_kinds:
        uid = lookup(name)
        where = f"uid {uid}" if uid is not None else "absent from the directory at start"
        notes.append(f"identity.accounts.{name}: kind {account_kinds[name]!r}, {where}")
    return notes


def has_access_acl(path: Path, platform: str) -> bool | None:
    """Whether an access control list widens a directory beyond its mode.

    Only the two errnos that mean "this file carries no such attribute" are
    an absence; every other failure — a permission error, an I/O error —
    leaves the answer unknown, and an unknown is never proof of absence
    (article 2). None also covers a platform with no reader (rule S6); which
    of the two it is follows from the platform.
    """
    if platform != "linux":
        return None
    try:
        os.getxattr(str(path), _ACL_ATTRIBUTE)
    except OSError as error:
        if error.errno in _NO_SUCH_ATTRIBUTE:
            return False
        return None
    return True


def facts_of(path: Path, platform: str) -> DirectoryFacts:
    """What `stat` says about one directory, for the pure protection rule."""
    resolved = path.resolve()
    st = os.stat(resolved)
    return DirectoryFacts(
        name=str(resolved),
        mode=st.st_mode,
        uid=st.st_uid,
        is_directory=stat_module.S_ISDIR(st.st_mode),
        has_access_acl=has_access_acl(resolved, platform),
    )


def ancestor_facts_of(path: Path, platform: str) -> tuple[DirectoryFacts, ...]:
    """What `stat` says about every directory above `path`, nearest first."""
    return tuple(facts_of(parent, platform) for parent in path.resolve().parents)


def protect_directory(directory: Path, *, daemon_uid: int, platform: str) -> str:
    """Refuse to start unless nobody but the daemon and root can write the place."""
    resolved = directory.resolve()
    if not resolved.is_dir():
        raise StartRefused("socket_directory_missing", str(resolved))
    verdict = directory_protection(
        st=facts_of(resolved, platform),
        ancestors=ancestor_facts_of(resolved, platform),
        daemon_uid=daemon_uid,
        platform=platform,
    )
    if verdict.refusal is not None:
        raise StartRefused(verdict.refusal, verdict.detail)
    return f"acl: {verdict.acl}"


def create_parent_directory(directory: Path, mode: int) -> None:
    """Create the directory, and every level of it that is missing, at `mode`.

    `Path.mkdir(parents=True)` applies its mode to the leaf alone: every level
    it creates above the leaf arrives at `0o777 & ~umask`, so under a
    permissive umask a per-user daemon created a world-writable ancestor of its
    own local address — the exact condition rule S4 refuses. It then refused to
    start on it, and went on refusing, because nothing removes the directory
    when the daemon exits. The mask is narrowed for the whole walk as well, so
    the mode is what the level arrives at rather than what it is asked for
    (article 6, rules L2 and S4).
    """
    missing: list[Path] = []
    level = directory
    while not level.exists():
        missing.append(level)
        if level.parent == level:
            break
        level = level.parent
    with _narrowed_umask(0o777 & ~mode):
        for level in reversed(missing):
            level.mkdir(mode=mode, exist_ok=True)


def clear_stale_address(path: Path) -> None:
    """Unlink a name nothing is listening at, and refuse when something is.

    Nothing but a local address is ever unlinked: a regular file at the name
    means somebody put it there, and the daemon does not know better.
    """
    if not path.is_symlink() and not path.exists():
        return
    st = os.lstat(path)
    if not stat_module.S_ISSOCK(st.st_mode):
        raise StartRefused("socket_in_use", f"a file that is not a local address is at {path}")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(path))
    except ConnectionRefusedError:
        os.unlink(path)
        return
    except OSError as error:
        raise StartRefused("socket_in_use", f"{path}: {error}") from error
    else:
        raise StartRefused("socket_in_use", f"a daemon is already listening at {path}")
    finally:
        probe.close()


def verify_bound_name(bound: object) -> str:
    """Refuse a name that has no file, and therefore no admission list.

    The abstract namespace of Linux has no file, so it has no permissions, so
    it has no admission list; it is not a deployment form (rule L4).
    """
    if not isinstance(bound, str | bytes):
        raise StartRefused("socket_not_unix", f"the bound name is {bound!r}")
    name = bound.decode(errors="surrogateescape") if isinstance(bound, bytes) else bound
    if not name or name.startswith("\0"):
        raise StartRefused("socket_abstract_or_unnamed", f"the bound name is {name!r}")
    return name


class _CachedDirectory:
    """One resolution, answered twice: once for admission, once for the principal.

    What it caches is the core's own value, never the directory's object. Two
    answers to one question have to be one answer, and an object the directory
    still owns is not one answer — it is one name that may read differently the
    second time (article 3, article 6 rule G1).
    """

    VERSION: Final[int] = 1

    def __init__(self, directory: AccountDirectory) -> None:
        self._directory = directory
        self._accounts: dict[int, Account | None] = {}
        self._group_ids: dict[tuple[str, int], tuple[int, ...]] = {}
        self._group_names: dict[int, str | None] = {}

    def account(self, uid: int) -> Account | None:
        if uid not in self._accounts:
            self._accounts[uid] = account_of(self._directory, uid)
        return self._accounts[uid]

    def group_ids(self, name: str, primary_gid: int) -> tuple[int, ...]:
        key = (name, primary_gid)
        if key not in self._group_ids:
            self._group_ids[key] = group_ids_of(self._directory, name, primary_gid)
        return self._group_ids[key]

    def group_name(self, gid: int) -> str | None:
        if gid not in self._group_names:
            self._group_names[gid] = group_name_of(self._directory, gid)
        return self._group_names[gid]


class Daemon:
    """One listener, one identity per connection, and nothing else listening."""

    def __init__(
        self,
        settings: Settings,
        *,
        platform: str,
        directory: AccountDirectory,
        peer_identity: PeerIdentity | None = None,
        clock: Clock | None = None,
        evidence: RecordCollector | None = None,
        daemon_uid: int | None = None,
        socket_gid: int | None = None,
        generation: int = 1,
        account_uid: Callable[[str], int | None] | None = None,
        services: object | None = None,
        composer: Callable[[], object | None] | None = None,
        overflow_ids: tuple[int | None, int | None] | None = None,
    ) -> None:
        """Read the overflow ids from this host, unless a composition supplies them.

        The ids are read from the host at start (rule L8) unless a composition
        supplies them, which only a test simulating another platform does — a
        simulation reading the real host's Linux-only kernel file is not a
        simulation (article 2). The daemon's own composition never passes it.
        """
        self.settings = settings
        self.platform = platform
        self.directory = directory
        self.clock = clock or SystemClock()
        self.evidence = evidence or RecordCollector()
        # What this deployment composed behind the surface, or nothing. Typed
        # as an object here on purpose: the transport binds a connection to an
        # identity and knows no application service, and `bootstrap` is the one
        # module that knows both (article 4).
        self.services = services
        # Or what will compose it, called in `start()` after the drop and before
        # `listen()` (rule L2a): the authority's start check and the store's
        # first append are made by the account that will read and append for
        # the daemon's whole life, not by the root that bound the address.
        self._composer = composer
        self.generation = generation
        self.daemon_uid = os.geteuid() if daemon_uid is None else daemon_uid
        # The daemon's own group, resolved beside its own uid. Never
        # `socket_gid`: that is the admission list, and the two are the same
        # only by coincidence (article 7). `_resolve_principal` sets it in
        # system mode; elsewhere the daemon keeps the group it was started in.
        self.daemon_gid = os.getegid()
        self.socket_gid = socket_gid
        try:
            self.peer_identity = peer_identity or select_peer_identity(
                platform, clock=self.clock.now
            )
        except PeerIdentityUnsupported as error:
            raise StartRefused("peer_identity_unsupported", str(error)) from error
        if overflow_ids is None:
            overflow_ids = read_overflow_ids(platform)
        self.overflow_uid, self.overflow_gid = overflow_ids
        self.account_uid = account_uid
        self.acl_note = ""
        self.start_notes: list[str] = []
        self._server: _Server | None = None
        self._serving = False
        self._stopped = False
        self._workers = ThreadPoolExecutor(max_workers=8, thread_name_prefix="directory")

    # -- start ----------------------------------------------------------------

    def _resolve_principal(self) -> None:
        """The uid the directory check accepts and the client expects (rule M2).

        In system mode that is uid 0, or the account `run_as` names — resolved
        before the check, not after it, so a directory the configured account
        owns is one of the two owners the rule admits.
        """
        if self.settings.mode != SYSTEM:
            return
        if not self.settings.run_as:
            self.daemon_uid = 0
            self.daemon_gid = 0
            return
        from .nss_directory import account_primary_gid, account_uid

        uid = account_uid(self.settings.run_as)
        gid = account_primary_gid(self.settings.run_as)
        if uid is None or gid is None:
            raise StartRefused("run_as_unknown", self.settings.run_as)
        self.daemon_uid = uid
        self.daemon_gid = gid

    def _look_up_account(self, name: str) -> int | None:
        if self.account_uid is not None:
            return self.account_uid(name)
        from .nss_directory import account_uid

        return account_uid(name)

    def start(self) -> None:
        """Everything that must be true before the daemon listens."""
        self._resolve_principal()
        self.start_notes = account_kind_notes(
            self.settings.account_kinds, lookup=self._look_up_account
        )
        path = Path(self.settings.socket_path)
        parent = path.parent
        if self.settings.mode == PER_USER:
            with _refusing("socket_directory_missing", f"creating {parent}"):
                create_parent_directory(parent, directory_mode(self.settings.mode))
        elif not parent.is_dir():
            raise StartRefused("socket_directory_missing", str(parent))
        # A directory whose protection could not be read is not a directory
        # proved protected, and an unknown is never a pass (article 2, rule S3).
        with _refusing("socket_directory_unprotected", f"reading {parent}"):
            self.acl_note = protect_directory(
                parent, daemon_uid=self.daemon_uid, platform=self.platform
            )
        # A name this daemon cannot clear is a name it cannot have (rule L7).
        with _refusing("socket_in_use", f"clearing {path}"):
            clear_stale_address(path)
        from .http_surface import RequestHandler

        server = _Server(str(path), RequestHandler, bind_and_activate=False)
        server.daemon = self
        bound = False
        try:
            with (
                _refusing("socket_address_denied", f"binding {path}"),
                _narrowed_umask(umask_for(self.settings.mode)),
            ):
                server.server_bind()
            bound = True
            verify_bound_name(server.socket.getsockname())
            if server.socket.family != socket.AF_UNIX:
                raise StartRefused("socket_not_unix", f"family {server.socket.family!r}")
            self._set_permissions(path)
            self._drop_privileges()
            self._compose()
            with _refusing("socket_address_denied", f"listening at {path}"):
                server.server_activate()
        except BaseException:
            server.server_close()
            if bound:
                # Only an address this start created is this start's to
                # remove. A bind that failed left whatever was already at the
                # name — a live daemon's address included — and rule L7 reads
                # "success means a daemon is listening", not "was".
                with suppress(OSError):
                    os.unlink(path)
            raise
        self._server = server

    def _set_permissions(self, path: Path) -> None:
        expected_mode = final_file_mode(self.settings.mode)
        if self.settings.mode == SYSTEM and self.socket_gid is None:
            raise StartRefused("socket_group_unknown", self.settings.group)
        with _refusing("socket_permissions_denied", f"setting the owner and mode of {path}"):
            if self.settings.mode == SYSTEM:
                os.chown(path, 0, self.socket_gid)
            os.chmod(path, expected_mode)
            st = os.stat(path)
        if stat_module.S_IMODE(st.st_mode) != expected_mode:
            raise StartRefused(
                "socket_mode_invalid",
                f"{path} carries {oct(stat_module.S_IMODE(st.st_mode))}, "
                f"expected {oct(expected_mode)}",
            )
        expected_owner = 0 if self.settings.mode == SYSTEM else self.daemon_uid
        if st.st_uid != expected_owner:
            raise StartRefused("socket_mode_invalid", f"{path} is owned by uid {st.st_uid}")
        if self.settings.mode == SYSTEM and st.st_gid != self.socket_gid:
            # The group is the admission list (article 6), so a `chown` the
            # filesystem reported as done but did not install would otherwise
            # reach listen() with no admission list at all.
            raise StartRefused(
                "socket_mode_invalid",
                f"{path} carries group {st.st_gid}, expected the configured group "
                f"{self.socket_gid}",
            )

    def _drop_privileges(self) -> None:
        """The irreversible calls, never the effective-only variants.

        The group is the account's own, never `socket.group`. `socket.group` is
        the admission list: it says which principals the kernel lets reach the
        address, and the daemon needs nothing from it once rule M3's
        `chown root:group` has run, which is before this. A daemon whose primary
        group *is* the governed principals' group creates every file it writes
        in a group they hold, and article 7's "no principal but that one and
        root can write or replace the store" is then one mode bit from untrue.

        `initgroups` is asked for the same group for the same reason. It sets
        the supplementary list to the memberships the directory records for the
        account, plus the group named here; naming the admission list here
        leaves the account's own group out of its own credentials entirely,
        which a root container showed it doing (`groups=[90000]` for an account
        whose groups are 4242 and 90000). Rule M3 fixes the three calls and
        their order and is silent on the group, so article 7 decides it.
        """
        if self.settings.mode != SYSTEM or not self.settings.run_as:
            return
        with _refusing("privileges_not_dropped", f"becoming {self.settings.run_as}"):
            os.initgroups(self.settings.run_as, self.daemon_gid)
            os.setgid(self.daemon_gid)
            os.setuid(self.daemon_uid)

    def _compose(self) -> None:
        """Compose the other blocks as the account the daemon now is (rule L2a).

        Every check before this point ran as whoever started the daemon, and in
        system mode that is root, which the host refuses nothing. A policy file
        read as root, and a chain file created as root, say nothing about what
        the dropped daemon can read and append; the first root run of system
        mode started healthy on both and then answered every ask as retryable,
        or served decisions it could never record (articles 2 and 10). So the
        composition happens here — after the irreversible calls, before
        `listen()` — and a deployment its running account cannot compose never
        listens: the refusal is a start refusal, by name, like every other.
        """
        if self._composer is None:
            return
        self.services = self._composer()

    # -- serving --------------------------------------------------------------

    def serve_forever(self) -> None:
        assert self._server is not None
        self._serving = True
        try:
            self._server.serve_forever(poll_interval=0.05)
        finally:
            self._serving = False

    def stop(self) -> None:
        """Stop once. A second stop has nothing left to ask for.

        What the composition started is stopped here, and stopping it twice is
        not free: the evidence emitter's flush waits out its whole timeout for a
        worker that has already returned, so a supervisor that stops a stopped
        daemon would wait seconds for nothing.
        """
        if self._stopped:
            return
        self._stopped = True
        if self._server is not None:
            if self._serving:
                self._server.shutdown()
            self._server.server_close()
            with suppress(OSError):
                os.unlink(self.settings.socket_path)
            self._server = None
        self._workers.shutdown(wait=False)
        if self.services is not None:
            self.services.close()  # type: ignore[attr-defined]

    # -- identity -------------------------------------------------------------

    def establish(self, connection: socket.socket) -> ConnectionIdentity:
        """Read the kernel's record of the peer, before a byte of the connection.

        When the operating system delivers none, the connection carries none:
        a `PeerCredential` is what the kernel said, so inventing one would
        put words in its mouth (rule P6).
        """
        now = self._now()
        try:
            # The credential is the core's own from here on: it is read at
            # admission and again for every record this connection leaves, and
            # those must be reads of one answer (rule P2).
            credential = credential_of(self.peer_identity, connection)
        except (PeerCredentialUnavailable, ForeignValueRefused):
            identity = self._new_identity(None, now)
            identity.refuse("peer_credential_unavailable")
            return identity
        return self._new_identity(credential, now)

    def _now(self) -> datetime:
        """One instant from the clock port, as a value this daemon owns.

        Every instant here is written into a record or into a refresh deadline,
        so it is read once and kept as the core's own: a `datetime` subclass an
        adapter returns answers the arithmetic and the text itself.
        """
        return core_owned_instant(self.clock.now())

    def _new_identity(self, credential: PeerCredential | None, now: datetime) -> ConnectionIdentity:
        return ConnectionIdentity(
            connection_id=str(uuid.uuid4()),
            accepted_at=now.isoformat(),
            socket_path=self.settings.socket_path,
            mode=self.settings.mode,
            peer=credential,
        )

    def on_connection(self, identity: ConnectionIdentity) -> None:
        """Refuse or resolve, once, before the first request is read."""
        if identity.status == REFUSED:
            self._record_opened(identity)
            return
        if identity.peer is not None and is_unmapped(
            identity.peer,
            overflow_uid=self.overflow_uid if self.overflow_uid is not None else -1,
            overflow_gid=self.overflow_gid if self.overflow_gid is not None else -1,
        ):
            identity.refuse("peer_uid_unmapped")
            self._record_opened(identity)
            return
        self.resolve(identity)
        self._record_opened(identity)

    def resolve(self, identity: ConnectionIdentity) -> str | None:
        """Consult the directory, admit, and bind — off the accept loop, bounded."""
        now = self._now()
        try:
            outcome = self._workers.submit(self._consult, identity, now).result(
                timeout=self.settings.resolution_timeout_seconds
            )
        except Exception:
            # Any failure of the directory, timeout included, is an unknown and
            # never a verdict: article 2, article 3. The attempt is due again
            # at once, so the next request on this connection repeats it and
            # the wait is never longer than the documented lifetime (rule G5).
            identity.mark_unknown(now, self.settings.group_lifetime_seconds)
            return None
        refusal, principal = outcome
        before = identity.principal
        if (
            before is not None
            and principal is not None
            and differs_beyond_establishment(before, principal)
        ):
            # What the directory now says, beside what it said before —
            # recorded before any refusal, so the change that caused a
            # revocation is the change the evidence carries (rules G3, A6).
            self._record_change(identity, now, before, principal)
        if refusal is not None:
            identity.refuse(refusal)
            return refusal
        identity.bind(principal, now, self.settings.group_lifetime_seconds)
        return None

    def _record_change(
        self,
        identity: ConnectionIdentity,
        now: datetime,
        before: Principal,
        after: Principal,
    ) -> None:
        """One record per chain the connection has touched, with both sides."""
        for scope in sorted(identity.touched_scopes) or [LOCAL_SCOPE]:
            self.evidence.append(
                evidence_records.principal_changed(
                    identity.connection_id, now.isoformat(), before, after, scope
                )
            )

    def _consult(
        self, identity: ConnectionIdentity, now: datetime
    ) -> tuple[str | None, Principal | None]:
        """Ask the directory once, then admit and build from the one answer.

        A connection that already carries a principal has its new one built
        even when admission now fails, so the change that refused it is the
        change the evidence records (rule G3). A peer refused the first time
        it is seen never had one, and none is built for it (rule E4).
        Nothing is bound to the connection here.
        """
        directory = _CachedDirectory(self.directory)
        verdict = admit(
            credential=identity.peer,
            mode=self.settings.mode,
            daemon_uid=self.daemon_uid,
            socket_gid=self.socket_gid,
            directory=directory,
        )
        if not verdict.admitted and identity.principal is None:
            return verdict.refusal, None
        account, resolution = resolve_identity(directory, identity.peer.uid, identity.peer.gid)
        principal = build_principal(
            identity.peer,
            account,
            resolution,
            kind=kind_for(account, self.settings.account_kinds),
            at=now.isoformat(),
        )
        return verdict.refusal, principal

    def refresh_if_due(self, identity: ConnectionIdentity) -> str | None:
        """Re-resolve a live connection whose identity has reached its lifetime."""
        if identity.status == REFUSED:
            return identity.refusal
        if not identity.needs_lookup(self._now()):
            return None
        return self.resolve(identity)

    def touch(self, identity: ConnectionIdentity, scope: str) -> None:
        """Record the connection's identity as its first record on a scope's chain."""
        if scope in identity.touched_scopes:
            return
        identity.touched_scopes.add(scope)
        self.evidence.append(evidence_records.connection_opened(identity, scope))

    def _record_opened(self, identity: ConnectionIdentity) -> None:
        self.touch(identity, LOCAL_SCOPE)

    def on_close(self, identity: ConnectionIdentity) -> None:
        at = self._now().isoformat()
        for scope in sorted(identity.touched_scopes) or [LOCAL_SCOPE]:
            self.evidence.append(
                evidence_records.connection_closed(identity.connection_id, at, scope)
            )

    # -- delegation -----------------------------------------------------------

    def read_delegation(self, document: Mapping[str, object]) -> Delegation | None:
        """Read the optional declaration, refusing one outside its bounds."""
        return Delegation.from_request_member(document.get("delegation"))


class _Server(ThreadingMixIn, UnixStreamServer):
    """One listener. The credential is read here, in the accept loop itself."""

    daemon_threads = True
    daemon: Daemon
    request_queue_size = 64

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.pending: WeakKeyDictionary[socket.socket, ConnectionIdentity] = WeakKeyDictionary()
        super().__init__(*args, **kwargs)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        self.pending[connection] = self.daemon.establish(connection)
        return connection, address

    def finish_request(self, request: Any, client_address: Any) -> None:
        identity = self.pending.pop(request, None)
        self.RequestHandlerClass(request, client_address, self, identity=identity)  # type: ignore[call-arg]

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A defect outside the request loop, recorded rather than discarded.

        `socketserver` calls this for an exception `handle_one_request` did not
        answer — one raised in `setup` or in `finish`. It was `pass`, so the
        connection closed with nothing written and nothing recorded, which is
        indistinguishable from a daemon that died (article 2).
        """
        del request, client_address
        LOG.error("the daemon failed on a connection at %s", self.server_address, exc_info=True)


def assemble(
    settings: Settings,
    *,
    platform: str,
    directory: AccountDirectory | None = None,
    peer_identity: PeerIdentity | None = None,
    clock: Clock | None = None,
    evidence: RecordCollector | None = None,
) -> Daemon:
    """Build the daemon a deployment asked for, refusing what the host denies.

    The composition of the other blocks is handed to the daemon to perform in
    `start()`, after the drop and before it listens (rule L2a): a deployment
    that configured a policy authority its running account cannot have never
    listens (article 3), and the check that says so is made by that account
    rather than by the root that bound the address (article 2).
    """
    from ..bootstrap import compose
    from .nss_directory import NssAccountDirectory, group_id

    socket_gid = None
    if settings.mode == SYSTEM:
        if os.geteuid() != 0:
            raise StartRefused("run_as_requires_root", "system mode binds as root and then drops")
        socket_gid = group_id(settings.group)
        if socket_gid is None:
            raise StartRefused("socket_group_unknown", settings.group)
    daemon_uid = os.geteuid()
    daemon_gid = os.getegid()
    if settings.mode == SYSTEM and settings.run_as:
        from .nss_directory import account_primary_gid, account_uid

        resolved = account_uid(settings.run_as)
        resolved_gid = account_primary_gid(settings.run_as)
        if resolved is None or resolved_gid is None:
            raise StartRefused("run_as_unknown", settings.run_as)
        daemon_uid = resolved
        # The account's own group, never the admission list (article 7): it is
        # what the evidence root must carry, and what the daemon drops to.
        daemon_gid = resolved_gid
    return Daemon(
        settings,
        platform=platform,
        directory=directory or NssAccountDirectory(),
        peer_identity=peer_identity,
        clock=clock,
        evidence=evidence,
        socket_gid=socket_gid,
        composer=lambda: compose(
            settings,
            daemon_uid=daemon_uid,
            daemon_gid=daemon_gid,
            administrator_gid=socket_gid,
            platform=platform,
        ),
    )
