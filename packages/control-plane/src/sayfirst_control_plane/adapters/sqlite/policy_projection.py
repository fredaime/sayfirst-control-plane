# SPDX-License-Identifier: Apache-2.0
"""A disposable SQLite materialization of the policy file."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import datetime
from pathlib import Path

from sayfirst_contract.decisions import Outcome

from ...domain.policy import PrincipalReference, Rule
from ...ports.policy_projection import ProjectedPolicy
from ...ports.policy_store import LoadedPolicy

_SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_projection (
    policy_version TEXT PRIMARY KEY,
    format INTEGER NOT NULL,
    loaded_at TEXT NOT NULL,
    rule_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_rule (
    rule_id TEXT PRIMARY KEY,
    capability TEXT NOT NULL,
    scope TEXT NOT NULL,
    principals_json TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL,
    grant_lifetime_seconds INTEGER,
    arguments_digest TEXT
);
"""


class SqlitePolicyProjection:
    VERSION = 1
    KIND = "database"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._trace_callback: Callable[[str], None] | None = None
        with closing(self._connect()) as database:
            database.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        database = sqlite3.connect(self.path)
        if self._trace_callback is not None:
            database.set_trace_callback(self._trace_callback)
        return database

    def rebuild(self, loaded: LoadedPolicy) -> None:
        with closing(self._connect()) as database, database:
            database.execute("DELETE FROM policy_rule")
            database.execute("DELETE FROM policy_projection")
            database.execute(
                "INSERT INTO policy_projection VALUES (?, ?, ?, ?)",
                (
                    loaded.policy_version,
                    loaded.policy.format,
                    loaded.loaded_at.isoformat(),
                    len(loaded.policy.rules),
                ),
            )
            database.executemany(
                "INSERT INTO policy_rule VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        rule.rule_id,
                        rule.capability,
                        rule.scope,
                        json.dumps([str(value) for value in rule.principals]),
                        rule.outcome.value,
                        rule.reason,
                        rule.grant_lifetime_seconds,
                        rule.arguments_digest,
                    )
                    for rule in loaded.policy.rules
                ),
            )

    def current(self) -> ProjectedPolicy | None:
        with closing(self._connect()) as database:
            header = database.execute(
                "SELECT policy_version, format, loaded_at, rule_count FROM policy_projection"
            ).fetchone()
            if header is None:
                return None
            rows = database.execute(
                """SELECT rule_id, capability, scope, principals_json, outcome, reason,
                          grant_lifetime_seconds, arguments_digest
                   FROM policy_rule ORDER BY rowid"""
            ).fetchall()
        rules = tuple(self._read_rule(row) for row in rows)
        return ProjectedPolicy(
            policy_version=header[0],
            format=header[1],
            loaded_at=datetime.fromisoformat(header[2]),
            rule_count=header[3],
            rules=rules,
        )

    def clear(self) -> None:
        with closing(self._connect()) as database, database:
            database.execute("DELETE FROM policy_rule")
            database.execute("DELETE FROM policy_projection")

    @staticmethod
    def _read_rule(row: tuple[object, ...]) -> Rule:
        references = []
        for raw in json.loads(str(row[3])):
            kind, name = raw.split(":", 1)
            references.append(PrincipalReference(kind, name))  # type: ignore[arg-type]
        return Rule(
            rule_id=str(row[0]),
            capability=str(row[1]),
            scope=str(row[2]),
            principals=tuple(references),
            outcome=Outcome(str(row[4])),
            reason=str(row[5]),
            grant_lifetime_seconds=row[6] if isinstance(row[6], int) else None,
            arguments_digest=row[7] if isinstance(row[7], str) else None,
        )
