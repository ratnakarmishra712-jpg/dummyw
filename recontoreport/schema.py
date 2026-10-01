"""Shared enums and the normalized result contract all phases write against.

Keeping these as plain enums/dataclasses (separate from the SQLAlchemy models)
gives phase modules a stable, import-light vocabulary for normalizing tool output
before it is persisted.
"""

from __future__ import annotations

import enum


class TargetStatus(str, enum.Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AssetType(str, enum.Enum):
    SUBDOMAIN = "subdomain"
    ENDPOINT = "endpoint"
    FILE = "file"
    JS_FILE = "js_file"
    API_ROUTE = "api_route"
    WEBSOCKET = "websocket"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
        }
        return order[self.value]


class Confidence(str, enum.Enum):
    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


class EvidenceType(str, enum.Enum):
    HTTP_TRANSACTION = "http_transaction"
    SCREENSHOT = "screenshot"
    DNS_CALLBACK = "dns_callback"
    DIFF = "diff"


# Interesting file extensions the directory bruteforce step flags specifically.
SENSITIVE_FILE_MARKERS = (".git", ".bak", ".zip", ".env", ".sql", ".old", ".swp")
