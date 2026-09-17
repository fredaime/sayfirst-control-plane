# SPDX-License-Identifier: Apache-2.0
"""What a deployment may say to this daemon, and why it may refuse to start.

A daemon that cannot hold article 6's promises does not run holding fewer of
them: it exits 78 with one reason on standard error, before it listens. These
reasons are the server's own vocabulary, tested by name and never part of the
contract — a peer never sees one, because a refused start serves nobody.

There is no key here whose name contains "host" or "port", and there is no
way to ask for one. Loopback is not an exception (article 6).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final

from sayfirst_contract.artifacts import domain_schema
from sayfirst_contract.binding.http_unix_socket.addresses import (
    sun_path_limit as published_sun_path_limit,
)

EX_CONFIG: Final[int] = 78

DEFAULT_GROUP_LIFETIME_SECONDS: Final[int] = 60
GROUP_LIFETIME_BOUNDS: Final[tuple[int, int]] = (1, 3600)
DEFAULT_RESOLUTION_TIMEOUT_SECONDS: Final[int] = 5
RESOLUTION_TIMEOUT_BOUNDS: Final[tuple[int, int]] = (1, 60)

PER_USER_KIND: Final[str] = "user"
PER_USER: Final[str] = "per_user"
SYSTEM: Final[str] = "system"
MODES: Final[tuple[str, ...]] = (PER_USER, SYSTEM)

EVERYONE_GROUPS: Final[tuple[str, ...]] = ("users", "staff", "everyone", "nogroup", "nobody")
"""Groups a host gives every account by default.

The group of the local address *is* the admission list (article 6), so an
admission list that admits everyone is a loopback port with extra steps. An
administrator who wants one of these edits this constant and owns the
consequence.
"""

START_REFUSALS: Final[frozenset[str]] = frozenset(
    {
        "socket_directory_unprotected",
        "socket_directory_missing",
        "socket_mode_invalid",
        "socket_path_too_long",
        "socket_path_not_absolute",
        "socket_in_use",
        "socket_group_unknown",
        "socket_group_is_everyone",
        "socket_not_unix",
        "socket_abstract_or_unnamed",
        "run_as_unknown",
        "run_as_requires_root",
        "peer_identity_unsupported",
        "overflow_id_unreadable",
        "mode_invalid",
        "group_lifetime_out_of_bounds",
        "configuration_unreadable",
        "configuration_unprotected",
        "socket_address_denied",
        "socket_permissions_denied",
        "privileges_not_dropped",
        "policy_unavailable_at_start",
        "evidence_root_unusable",
        "plugin_composition_refused",
        "decision_store_unusable",
        "policy_archive_unusable",
        "recovery_store_unusable",
    }
)
"""Every reason this daemon may exit 78 with.

The last four name what the *host* refused rather than what the deployment
asked for: a configuration file that cannot be read or parsed, a `bind` or
`listen` the kernel would not perform, a `chown`/`chmod` that could not install
the admission list, and a privilege drop that did not happen. Each of those was
an `OSError` reaching `main()` — exit 1 and a traceback, where the deployment
document publishes 78 and one sentence, and where a supervisor keyed on
`EX_CONFIG` reads an ordinary crash (article 2).

The last three name what the *composition* refused: a policy authority that
could not be read or is not protected where it stands, an evidence root the
daemon cannot keep a chain in, and a plugin composition that could not be
resolved. A daemon that cannot decide, cannot record, or does not know what it
composed serves nobody, so it refuses to start rather than serving a surface
that would answer an unknown as a fact (articles 2, 3 and 8).

The last three name a durable authority of block 2.7 the daemon could not
prove usable after the privilege drop and before listening: a decision root
another writer holds or this account cannot recover, a policy archive that
cannot keep the start version, and a recovery journal it cannot read or
append. Each is a storage or protection failure, never a historical
discrepancy, which is reported in status and refuses no start (S8, S9).

One names the configuration file itself: in system mode, a configuration an
account other than root or its administrator group could write or replace
(article 8). It is checked where every other protection check is made — by the
account the daemon runs as, after the drop and before it listens — because
whoever can write that file chooses the address, the admission group, the
policy authority, the evidence root and the plugins every other check then
reads."""

_KIND_SCHEMA: Final[Mapping[str, object]] = domain_schema("principal")["properties"]["kind"]  # type: ignore[index]
"""The published bounds of a principal's kind, read from the contract itself."""

_SOCKET_KEYS: Final[frozenset[str]] = frozenset({"mode", "path", "group", "run_as"})
_POLICY_KEYS: Final[frozenset[str]] = frozenset({"path"})
_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset({"path"})
_IDENTITY_KEYS: Final[frozenset[str]] = frozenset(
    {"group_lifetime_seconds", "resolution_timeout_seconds", "accounts"}
)


class StartRefused(Exception):
    """The daemon will not start, and says which rule stopped it."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        if reason not in START_REFUSALS:
            raise AssertionError(f"unnamed start refusal {reason!r}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Settings:
    """Everything a deployment said, read once and bounded."""

    mode: str
    socket_path: str
    group: str
    run_as: str
    group_lifetime_seconds: int
    resolution_timeout_seconds: int
    account_kinds: Mapping[str, str]
    policy_path: str = ""
    """The authority a decision is read from, or `""` when none is configured.

    A deployment that names none composes no decision path at all, and the
    surface says so operation by operation rather than answering an absence as
    an empty policy (article 2). `bootstrap.compose` reads this key and nothing
    else decides whether the daemon can decide."""
    evidence_root: str = ""
    """Where the evidence chains live; required beside a policy authority."""
    configuration_path: str = ""
    """The file these words were read from, or `""` when a deployment named none.

    Article 8 protects the configuration in system mode by effective access, at
    start and again per decision request, and a check needs a name to make. This
    carries the one `--config` gave, so the file the daemon checks is the file
    the daemon read and never a second guess at where a configuration might be
    (articles 2 and 8). A deployment that named none — a daemon started with no
    `--config` at all, which reads no file and takes every default — carries
    `""`, and nothing claims a protection of a file that does not exist.

    It is kept as the deployment wrote it, made absolute against the working
    directory and never normalised: `os.path.normpath` collapses `link/..`
    before any component is looked at, and the component a `..` pops is a name
    that decides which file is reached. The walk in
    `access/effective_access.py` resolves the name itself, component by
    component, which is the only reading of a path that matches the kernel's."""
    plugin_selection: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    """The `[plugins]` table as the deployment wrote it, unparsed here.

    Article 8 gives the plugin configuration shape to the contract
    distribution, which owns its reader; a second reader here would be a second
    answer to one question. This carries the table across to the bootstrap that
    hands it to that reader."""


def read_kind(name: str, value: object) -> str:
    """A configured kind, or a start refusal naming what is wrong with it.

    The registry of kinds is open (rule K1), but everything the daemon records
    and serves is a shape the contract publishes (article 13). A kind the
    published shape would not accept is therefore refused here, before the
    daemon starts, rather than escaping later inside a response document.
    """
    member = f"identity.accounts.{name}.kind"
    if not isinstance(value, str) or isinstance(value, bool):
        raise StartRefused("mode_invalid", f"{member} must be a string")
    if value != value.strip() or not value:
        raise StartRefused("mode_invalid", f"{member} must be a name, not blank or padded")
    if len(value) < int(_KIND_SCHEMA["minLength"]):  # type: ignore[arg-type]
        raise StartRefused("mode_invalid", f"{member} is shorter than the contract allows")
    if len(value) > int(_KIND_SCHEMA["maxLength"]):  # type: ignore[arg-type]
        raise StartRefused("mode_invalid", f"{member} is longer than the contract allows")
    limit = int(_KIND_SCHEMA["x-max-bytes"])  # type: ignore[arg-type]
    if len(value.encode()) > limit:
        raise StartRefused("mode_invalid", f"{member} is longer than {limit} bytes")
    return value


def sun_path_limit(platform: str) -> int:
    """How many bytes the kernel's address structure holds, terminator included.

    The number is the transport binding's (article 13), not this daemon's: the
    same bound decides whether this daemon may bind an address and whether the
    acceptance suites may compose one, and a second copy of it here would be a
    second answer waiting to disagree.
    """
    return published_sun_path_limit(platform)


def umask_for(mode: str) -> int:
    """The mask that makes the file arrive at its final permissions, never wider."""
    if mode == PER_USER:
        return 0o077
    if mode == SYSTEM:
        return 0o117
    raise ValueError(f"no umask for mode {mode!r}")


def directory_mode(mode: str) -> int:
    """The permissions every level of the parent directory must carry.

    Article 6: "the socket's parent directory is writable by the daemon's
    principal and root only". A daemon only creates one in per-user mode; in
    system mode the packager or the administrator does (rule L2).
    """
    if mode == PER_USER:
        return 0o700
    raise ValueError(f"no directory mode for mode {mode!r}")


def final_file_mode(mode: str) -> int:
    """The permissions the file must carry once it exists."""
    if mode == PER_USER:
        return 0o700
    if mode == SYSTEM:
        return 0o660
    raise ValueError(f"no file mode for mode {mode!r}")


def default_socket_path(
    mode: str,
    platform: str,
    *,
    environ: Mapping[str, str],
    home: str,
    directory_exists: Callable[[str], bool] | None = None,
) -> str:
    """The default local address of a mode on a platform.

    The runtime directory is used when it is set **and** names a directory
    that exists; a variable pointing at nothing selects the fallback rather
    than making the daemon create the place the variable named (rule L2).
    """
    if mode == SYSTEM:
        root = "/var/run" if platform == "darwin" else "/run"
        return f"{root}/sayfirst/daemon.sock"
    runtime = environ.get("XDG_RUNTIME_DIR", "")
    exists = directory_exists or os.path.isdir
    if runtime and exists(runtime):
        return f"{runtime.rstrip('/')}/sayfirst/daemon.sock"
    return f"{home.rstrip('/')}/.sayfirst/run/daemon.sock"


def _bounded_int(value: object, bounds: tuple[int, int], reason: str, member: str) -> int:
    low, high = bounds
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise StartRefused(reason, f"{member} must be a whole number from {low} to {high}")
    return value


def read_settings(
    document: Mapping[str, object],
    *,
    platform: str,
    environ: Mapping[str, str] | None = None,
    home: str = "/",
    configuration_path: str = "",
) -> Settings:
    """Read a deployment's own words, refusing anything the daemon cannot hold.

    `configuration_path` is where those words were read from, which the reader
    knows and the document does not say. It travels on the answer so that the
    protections article 8 asks for in system mode have a file to make: the one
    this call read, and no other.
    """
    socket_section = document.get("socket", {})
    identity_section = document.get("identity", {})
    policy_section = document.get("policy", {})
    evidence_section = document.get("evidence", {})
    plugins_section = document.get("plugins", {})
    if not all(
        isinstance(section, Mapping)
        for section in (
            socket_section,
            identity_section,
            policy_section,
            evidence_section,
            plugins_section,
        )
    ):
        raise StartRefused("mode_invalid", "each section must be a table")
    unknown = set(socket_section) - _SOCKET_KEYS
    if unknown:
        raise StartRefused("mode_invalid", f"socket.{sorted(unknown)[0]} is not a key")
    unknown = set(identity_section) - _IDENTITY_KEYS
    if unknown:
        raise StartRefused("mode_invalid", f"identity.{sorted(unknown)[0]} is not a key")
    for name, section, keys in (
        ("policy", policy_section, _POLICY_KEYS),
        ("evidence", evidence_section, _EVIDENCE_KEYS),
    ):
        unknown = set(section) - keys
        if unknown:
            raise StartRefused("mode_invalid", f"{name}.{sorted(unknown)[0]} is not a key")

    mode = socket_section.get("mode", PER_USER)
    if mode not in MODES:
        raise StartRefused("mode_invalid", f"socket.mode must be one of {', '.join(MODES)}")
    group = str(socket_section.get("group", ""))
    run_as = str(socket_section.get("run_as", ""))
    accounts = identity_section.get("accounts", {})
    if not isinstance(accounts, Mapping):
        raise StartRefused("mode_invalid", "identity.accounts must be a table")

    if mode == PER_USER:
        for member, value in (("socket.group", group), ("socket.run_as", run_as)):
            if value:
                raise StartRefused("mode_invalid", f"{member} has no meaning in {PER_USER} mode")
        if accounts:
            raise StartRefused(
                "mode_invalid", f"identity.accounts has no meaning in {PER_USER} mode"
            )
    else:
        if not group:
            raise StartRefused("socket_group_unknown", "socket.group is required in system mode")
        if group in EVERYONE_GROUPS:
            raise StartRefused(
                "socket_group_is_everyone",
                f"socket.group {group!r} is a group every account belongs to",
            )

    socket_path = socket_section.get("path") or default_socket_path(
        str(mode), platform, environ=environ or {}, home=home
    )
    socket_path = str(socket_path)
    if not socket_path.startswith("/"):
        raise StartRefused("socket_path_not_absolute", f"socket.path is {socket_path!r}")
    limit = sun_path_limit(platform)
    if len(socket_path.encode()) + 1 > limit:
        raise StartRefused(
            "socket_path_too_long",
            f"socket.path is {len(socket_path.encode()) + 1} bytes, the limit is {limit}",
        )

    lifetime = _bounded_int(
        identity_section.get("group_lifetime_seconds", DEFAULT_GROUP_LIFETIME_SECONDS),
        GROUP_LIFETIME_BOUNDS,
        "group_lifetime_out_of_bounds",
        "identity.group_lifetime_seconds",
    )
    timeout = _bounded_int(
        identity_section.get("resolution_timeout_seconds", DEFAULT_RESOLUTION_TIMEOUT_SECONDS),
        RESOLUTION_TIMEOUT_BOUNDS,
        "mode_invalid",
        "identity.resolution_timeout_seconds",
    )
    account_kinds = {}
    for name, entry in accounts.items():
        if not isinstance(entry, Mapping) or set(entry) - {"kind"}:
            raise StartRefused("mode_invalid", f"identity.accounts.{name} names only a kind")
        account_kinds[str(name)] = read_kind(str(name), entry.get("kind", PER_USER_KIND))
    policy_path = _absolute_path(policy_section.get("path"), "policy.path")
    evidence_root = _absolute_path(evidence_section.get("path"), "evidence.path")
    if policy_path and not evidence_root:
        # A daemon that decides and records nowhere would answer a decision it
        # holds no evidence for, which article 10 does not allow it to claim.
        raise StartRefused("mode_invalid", "evidence.path is required beside policy.path")
    if evidence_root and not policy_path:
        raise StartRefused("mode_invalid", "evidence.path has no meaning without policy.path")
    return Settings(
        mode=str(mode),
        socket_path=socket_path,
        group=group,
        run_as=run_as,
        group_lifetime_seconds=lifetime,
        resolution_timeout_seconds=timeout,
        account_kinds=account_kinds,
        configuration_path=configuration_path,
        policy_path=policy_path,
        evidence_root=evidence_root,
        plugin_selection={
            str(name): dict(entry) if isinstance(entry, Mapping) else {}
            for name, entry in plugins_section.items()
        },
    )


def _absolute_path(value: object, member: str) -> str:
    """One configured path, or `""` when the deployment named none."""
    if value is None:
        return ""
    if not isinstance(value, str) or not value:
        raise StartRefused("mode_invalid", f"{member} must be a path")
    if not value.startswith("/"):
        raise StartRefused("socket_path_not_absolute", f"{member} is {value!r}")
    return value
