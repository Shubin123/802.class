"""Capture-native, BSSID-scoped 802.11 application-classification pipeline.

The package deliberately does not import the historical simulator or legacy
checkpoints.  Its public contract starts with a raw monitor-mode observation,
scopes it to one infrastructure BSSID, and turns each client trace into a
versioned metadata feature window.
"""

from .contract import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION

__all__ = ["FEATURE_COLUMNS", "FEATURE_SCHEMA_VERSION"]
