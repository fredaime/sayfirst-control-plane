# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the published daemon and the composed daemon."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from _daemon import daemon as daemon
from composed_daemon import make_composed_daemon


@pytest.fixture
def composed(tmp_path: Path) -> Iterator[object]:
    with make_composed_daemon(tmp_path) as factory:
        yield factory
