# SPDX-License-Identifier: Apache-2.0
"""The domain contract's opaque scope syntax."""

from __future__ import annotations

import re
from typing import Final

SCOPE_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def scope_matches_contract(scope: str) -> bool:
    return SCOPE_PATTERN.fullmatch(scope) is not None


def validate_scope(scope: str) -> None:
    if not scope_matches_contract(scope):
        raise ValueError("scope does not match the contract")
