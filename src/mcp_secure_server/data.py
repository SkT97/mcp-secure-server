"""Synthetic, tenant-isolated records with no business-specific fields."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

TENANTS: tuple[str, ...] = ("north", "south")
RECORDS_PER_TENANT = 5
MIN_LIMIT = 1
MAX_LIMIT = 50
MAX_RECORD_ID_LENGTH = 32
NOT_FOUND = "Record not found."

_RECORD_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


@dataclass(frozen=True)
class Record:
    """A synthetic record scoped to exactly one tenant."""

    id: str
    tenant: str
    title: str
    body: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _build_store() -> dict[str, dict[str, Record]]:
    store: dict[str, dict[str, Record]] = {}
    for tenant in TENANTS:
        store[tenant] = {
            f"rec-{tenant}-{n}": Record(
                id=f"rec-{tenant}-{n}",
                tenant=tenant,
                title=f"Synthetic record {n}",
                body=f"Synthetic content {n} for tenant {tenant}.",
            )
            for n in range(1, RECORDS_PER_TENANT + 1)
        }
    return store


class RecordStore:
    """Tenant-scoped synthetic records.

    Every lookup receives the tenant explicitly (the caller must pass the
    tenant from the verified principal); an id belonging to another tenant
    is indistinguishable from an unknown id.
    """

    def __init__(self) -> None:
        self._by_tenant = _build_store()

    def list_for_tenant(self, tenant: str, limit: int) -> list[dict[str, str]]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError(f"limit must be an integer between {MIN_LIMIT} and {MAX_LIMIT}")
        if not MIN_LIMIT <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be an integer between {MIN_LIMIT} and {MAX_LIMIT}")
        records = sorted(self._by_tenant.get(tenant, {}).values(), key=lambda r: r.id)
        return [record.to_dict() for record in records[:limit]]

    def get_for_tenant(self, tenant: str, record_id: str) -> str | dict[str, str]:
        if not isinstance(record_id, str) or not _RECORD_ID_RE.match(record_id):
            return NOT_FOUND
        record = self._by_tenant.get(tenant, {}).get(record_id)
        if record is None:
            return NOT_FOUND
        return record.to_dict()
