# SPDX-License-Identifier: Apache-2.0
"""Startup, authoritative reload, change signalling, and projection rebuilds."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sayfirst_contract.policy import ProjectionStep

from ..domain.foreign import (
    ForeignValueRefused,
    core_owned,
    core_owned_input,
    core_owned_instant,
)
from ..domain.policy import core_owned_policy, core_owned_rule
from ..ports.policy_projection import PolicyProjection, ProjectedPolicy, projection_kind
from ..ports.policy_store import (
    LoadedPolicy,
    PolicyStore,
    PolicyUnavailable,
    ProtectionExpectation,
    ProtectionState,
    ProtectionVerdict,
)
from .events import Events, NullEvents


class PolicyStartRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class ProjectionStatus:
    kind: str
    policy_version: str | None
    in_step: ProjectionStep


@dataclass(frozen=True)
class PolicyStatus:
    authority: str
    policy_version: str
    format: int
    loaded_at: datetime
    rule_count: int
    projection: ProjectionStatus


class PolicyService:
    """Own the current authority version without using its projections to decide."""

    def __init__(
        self,
        store: PolicyStore,
        projections: Iterable[PolicyProjection],
        *,
        events: Events | None = None,
        reload_seconds: int = 2,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= reload_seconds <= 60:
            raise ValueError("policy reload interval must be between 1 and 60 seconds")
        self.store = store
        self.projections = tuple(projections)
        if not self.projections:
            raise ValueError("at least one policy projection must be composed")
        self.events = events or NullEvents()
        self.reload_seconds = reload_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._current: LoadedPolicy | None = None
        self._last_checked: datetime | None = None
        self._seen_failures: set[tuple[str, str]] = set()
        self._listeners: list[Callable[[str], None]] = []

    def _now(self) -> datetime:
        """One instant from the composed clock, as a value this service owns.

        The clock is a seam like any other (`domain/foreign.py`): an instant is
        written into a record and compared against another, and both live on the
        type, so a `datetime` subclass answers them itself.
        """
        return core_owned_instant(self._clock())

    @property
    def current_version(self) -> str:
        if self._current is None:
            raise RuntimeError("policy service has not started")
        return self._current.policy_version

    @property
    def current_loaded(self) -> LoadedPolicy:
        """The policy as last loaded, bytes included: what the archive keeps at start (A1)."""
        if self._current is None:
            raise RuntimeError("policy service has not started")
        return self._current

    @property
    def scopes_reached(self) -> frozenset[str]:
        """The scopes the current policy's rules name: each one a chain to be kept.

        A rule for a scope is a decision the daemon may serve in that scope,
        and a decision served is a record owed to that scope's chain (article
        10). The composition reads this once, at start, to prove every such
        chain before anything is served (rule L2a).
        """
        if self._current is None:
            raise RuntimeError("policy service has not started")
        return frozenset(rule.scope for rule in self._current.policy.rules)

    def on_version_change(self, listener: Callable[[str], None]) -> None:
        """Register a listener once; composing the same collaborator twice signals once."""
        if listener not in self._listeners:
            self._listeners.append(listener)

    def start(self, expectation: ProtectionExpectation) -> None:
        try:
            verdict = core_owned(
                ProtectionVerdict,
                self.store.protection_at_start(expectation),
                component=lambda path: None if path is None else Path(path),
                reason=lambda text: None if text is None else str(text),
            )
        except ForeignValueRefused as error:
            raise PolicyStartRefused(
                f"the policy authority answered no verdict: {error}"
            ) from error
        if verdict.kind is not ProtectionState.PROTECTED:
            if verdict.reason == "stat_failed":
                unavailable = self._answer()
                if isinstance(unavailable, PolicyUnavailable) and unavailable.reason == "absent":
                    raise PolicyStartRefused(unavailable.message)
            raise PolicyStartRefused(
                f"policy path {verdict.component} is {verdict.kind.value}: {verdict.reason}"
            )
        loaded = self._answer()
        if isinstance(loaded, PolicyUnavailable):
            raise PolicyStartRefused(loaded.message)
        self._current = loaded
        self._last_checked = self._now()
        self._rebuild(loaded)
        self.events.record(
            "policy.loaded",
            {
                "policy_version": loaded.policy_version,
                "rule_count": len(loaded.policy.rules),
                "path": str(getattr(self.store, "path", "unknown")),
            },
            at=loaded.loaded_at,
        )

    def load_for_decision(self) -> LoadedPolicy | PolicyUnavailable:
        if self._current is None:
            raise RuntimeError("policy service has not started")
        self._last_checked = self._now()
        loaded = self._answer()
        if isinstance(loaded, PolicyUnavailable):
            self._record_failure(loaded)
            return loaded
        self._seen_failures.clear()
        if loaded.policy_version != self._current.policy_version:
            self._change_to(loaded)
        return loaded

    def reload_if_due(self) -> bool:
        if self._current is None or self._last_checked is None:
            raise RuntimeError("policy service has not started")
        now = self._now()
        if now - self._last_checked < timedelta(seconds=self.reload_seconds):
            return False
        self._last_checked = now
        loaded = self._answer()
        if isinstance(loaded, PolicyUnavailable):
            self._record_failure(loaded)
            return True
        self._seen_failures.clear()
        if loaded.policy_version != self._current.policy_version:
            self._change_to(loaded)
        return True

    def status(self) -> PolicyStatus:
        if self._current is None:
            raise RuntimeError("policy service has not started")
        currents: list[ProjectedPolicy | None] = []
        for projection in self.projections:
            try:
                # A projection is a port (article 8) and this reads its version
                # twice — once to say whether it is in step, once to publish it.
                # Two reads of one name are two answers unless the value is the
                # core's own (articles 2, 3 and 13).
                answered = projection.current()
                currents.append(None if answered is None else _core_owned_projection(answered))
            except Exception:
                currents.append(None)
        behind = any(
            current is not None and current.policy_version != self._current.policy_version
            for current in currents
        )
        unknown = any(current is None for current in currents)
        in_step = (
            ProjectionStep.NO
            if behind
            else ProjectionStep.UNKNOWN
            if unknown
            else ProjectionStep.YES
        )
        kind = projection_kind(self.projections[0]) if len(self.projections) == 1 else "combined"
        versions = {current.policy_version for current in currents if current is not None}
        projected_version = next(iter(versions)) if len(versions) == 1 and not unknown else None
        return PolicyStatus(
            "file",
            self._current.policy_version,
            self._current.policy.format,
            self._current.loaded_at,
            len(self._current.policy.rules),
            ProjectionStatus(
                kind,
                projected_version,
                in_step,
            ),
        )

    def _answer(self) -> LoadedPolicy | PolicyUnavailable:
        """One load from the authority port, taken into the core before it is used.

        Article 3: the policy a decision is evaluated against and the version
        the decision record names must be one answer. The store owns the object
        it answered with, and this service keeps its answer for the daemon's
        life and re-reads it for every ask, so the answer is copied here — once,
        rules and all — and it is the copy that is kept.
        """
        answer = self.store.load()
        try:
            if isinstance(answer, PolicyUnavailable):
                return core_owned(PolicyUnavailable, answer, message=str)
            return core_owned(
                LoadedPolicy,
                answer,
                policy=core_owned_policy,
                policy_version=str,
                loaded_at=core_owned_instant,
                byte_length=int,
                content=_core_owned_bytes,
            )
        except ForeignValueRefused as error:
            return PolicyUnavailable("invalid", f"the policy authority answered no policy: {error}")

    def _change_to(self, loaded: LoadedPolicy) -> None:
        assert self._current is not None
        previous = self._current.policy_version
        self._current = loaded
        self._rebuild(loaded)
        self.events.record(
            "policy.version_changed",
            {
                "from": previous,
                "to": loaded.policy_version,
                "rule_count": len(loaded.policy.rules),
                "revision.reason": loaded.policy.revision_reason,
            },
            at=loaded.loaded_at,
        )
        for listener in tuple(self._listeners):
            listener(loaded.policy_version)

    def _rebuild(self, loaded: LoadedPolicy) -> None:
        """Rebuild every projection from the policy, each from a copy of its own.

        Article 3, input side. `loaded` is what this service goes on to serve
        and what every later projection is rebuilt from, and a projection is a
        port: handed the core's object, one `object.__setattr__` moved the
        version the next projection saw and the version the service answered
        with. The rules are rebuilt with it — `core_owned_policy` — because a
        rule is what a projection reads and what `evaluate` reads.
        """
        for projection in self.projections:
            try:
                projection.rebuild(
                    core_owned_input(
                        LoadedPolicy, loaded, policy=core_owned_policy, content=_core_owned_bytes
                    )
                )
            except Exception as exc:
                self.events.record(
                    "policy.projection_failed",
                    {
                        "adapter_kind": projection_kind(projection),
                        "reason": str(exc),
                    },
                    at=self._now(),
                )

    def _record_failure(self, unavailable: PolicyUnavailable) -> None:
        identity = (unavailable.reason, unavailable.message)
        if identity in self._seen_failures:
            return
        self._seen_failures.add(identity)
        self.events.record(
            "policy.reload_failed",
            {"reason": unavailable.reason, "message": unavailable.message},
            at=self._now(),
        )


def _core_owned_bytes(value: object) -> bytes | None:
    """The core's own copy of the bytes an authority read, or `None` for none supplied."""
    if value is None:
        return None
    if not isinstance(value, bytes | bytearray | memoryview):
        raise TypeError("policy content must be bytes")
    return bytes(value)


def _core_owned_projection(projected: object) -> ProjectedPolicy:
    """What a projection says it holds, as the core's own value."""
    return core_owned(
        ProjectedPolicy,
        projected,
        policy_version=str,
        format=int,
        loaded_at=core_owned_instant,
        rule_count=int,
        rules=lambda items: tuple(core_owned_rule(item) for item in items),
    )
