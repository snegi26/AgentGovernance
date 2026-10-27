# SPDX-License-Identifier: Apache-2.0
"""Handling of untrusted text: provenance-tagged quoting and instruction-shaped content flags.

The gateway never *interprets* untrusted text, so scanning is not the defence: the defence is
that no write completes without an engine verdict and a human approval. Flags exist to raise
the approval tier, put the attempt in front of a reviewer, and leave a trail in the evidence.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

POSSIBLE_INJECTION = "possible_injection"
PRIVILEGED_PROFILE = "privileged_profile_reference"

_INSTRUCTION_PATTERNS = [
    r"\bignore\b.{0,40}\b(instruction|rule|polic|guardrail|prompt)",
    r"\bdisregard\b.{0,40}\b(instruction|rule|polic|above|previous)",
    r"\b(system|developer)\s*(prompt|message|instruction)",
    r"\byou\s+are\s+now\b",
    r"\bact\s+as\b.{0,30}\b(admin|administrator|root|approver)",
    r"\b(approve|grant)\b.{0,30}\b(immediately|automatically|without)\b",
    r"\bdo\s+not\s+(tell|inform|log|record)\b",
    r"</?\s*(system|assistant|tool|instructions?)\s*>",
]
_PRIVILEGED = [r"\bSAP_ALL\b", r"\bSAP_NEW\b", r"\bS_A\.SYSTEM\b", r"\bGlobal\s+Administrator\b"]

_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_PATTERNS), re.IGNORECASE | re.DOTALL)
_PRIVILEGED_RE = re.compile("|".join(_PRIVILEGED), re.IGNORECASE)


def _normalise(text: str) -> str:
    # Fold compatibility forms (full-width letters, ligatures) and drop zero-width characters
    # so trivially obfuscated payloads still match.
    folded = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")


def scan_text(text: str) -> set[str]:
    normalised = _normalise(text)
    flags: set[str] = set()
    if _INSTRUCTION_RE.search(normalised):
        flags.add(POSSIBLE_INJECTION)
    if _PRIVILEGED_RE.search(normalised):
        flags.add(PRIVILEGED_PROFILE)
    return flags


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def scan_arguments(arguments: Mapping[str, Any], fields: Iterable[str]) -> list[str]:
    flags: set[str] = set()
    for name in fields:
        for text in _strings(arguments.get(name)):
            flags |= scan_text(text)
    return sorted(flags)


@dataclass(frozen=True, slots=True)
class UntrustedSpan:
    """Untrusted text plus where it came from, for passing to a model as *data*."""

    text: str
    source: str
    field: str

    def quoted(self) -> str:
        """JSON-quoted with provenance, so it can never close or open an instruction block."""
        return json.dumps(
            {"untrusted": True, "source": self.source, "field": self.field, "text": self.text}
        )
