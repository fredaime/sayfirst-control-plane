# SPDX-License-Identifier: Apache-2.0
"""Documented bounds used by later configuration composition."""

from typing import Final

GRADE_REEVALUATION_HELP: Final = (
    "Seconds between effective-access checks; this interval is the latency of detection "
    "of a store permission change (1 to 300 seconds)."
)
