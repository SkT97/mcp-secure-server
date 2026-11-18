"""Unit tests for the tenant-isolated synthetic record store."""

from __future__ import annotations

import pytest

from mcp_secure_server.data import (
    MAX_LIMIT,
    MIN_LIMIT,
    NOT_FOUND,
    RECORDS_PER_TENANT,
    RecordStore,
)


@pytest.fixture()
def store() -> RecordStore:
    return RecordStore()


def test_north_sees_only_north_records(store) -> None:
    records = store.list_for_tenant("north", MAX_LIMIT)
    assert len(records) == RECORDS_PER_TENANT
    assert all(r["tenant"] == "north" for r in records)


def test_south_sees_only_south_records(store) -> None:
    records = store.list_for_tenant("south", MAX_LIMIT)
    assert len(records) == RECORDS_PER_TENANT
    assert all(r["tenant"] == "south" for r in records)


def test_unknown_tenant_list_is_empty(store) -> None:
    assert store.list_for_tenant("east", 10) == []


def test_limit_is_respected(store) -> None:
    assert len(store.list_for_tenant("north", 3)) == 3
    assert len(store.list_for_tenant("north", MIN_LIMIT)) == 1
    assert len(store.list_for_tenant("north", MAX_LIMIT)) == RECORDS_PER_TENANT


@pytest.mark.parametrize("limit", [0, MAX_LIMIT + 1, 1000, -1, 3.5, "5"])
def test_out_of_bounds_limit_rejected(store, limit) -> None:
    with pytest.raises(ValueError):
        store.list_for_tenant("north", limit)


def test_get_own_record(store) -> None:
    record = store.get_for_tenant("north", "rec-north-1")
    assert isinstance(record, dict)
    assert record["id"] == "rec-north-1"
    assert record["tenant"] == "north"


def test_cross_tenant_get_indistinguishable_from_unknown(store) -> None:
    cross = store.get_for_tenant("north", "rec-south-1")
    unknown = store.get_for_tenant("north", "rec-north-999")
    assert cross == NOT_FOUND
    assert unknown == NOT_FOUND
    assert cross == unknown


def test_malformed_ids_are_not_found(store) -> None:
    for bad in ("rec-north-1".upper(), "../rec-north-1", "x" * 33, "", "rec north 1", "a/b"):
        assert store.get_for_tenant("north", bad) == NOT_FOUND
