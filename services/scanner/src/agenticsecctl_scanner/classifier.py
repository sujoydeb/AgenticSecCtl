"""Advisory classifier interface (FR-SCAN-3).

A classifier may raise a signal; it can never lower a deterministic severity, remove a finding, or approve a
tool. Its failure (exception, timeout, nonsense score) is ignored and the deterministic result stands.
"""
from __future__ import annotations

from typing import Protocol


class Classifier(Protocol):
    def classify(self, text: str) -> float:
        """Probability in [0, 1] that the text is an instruction aimed at the model."""
        ...


class NullClassifier:
    """The Phase 1 stub: no opinion."""

    def classify(self, text: str) -> float:
        return 0.0
