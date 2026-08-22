"""host-triage: one-shot connectivity triage for a host or service.

Runs DNS, ping, TCP, TLS-expiry and HTTP checks against a target and reports
a human-readable table or machine-readable JSON, with a meaningful exit code.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
