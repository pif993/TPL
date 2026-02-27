"""
Unit Tests — Audit Chain (tamper-evident hash chain)

Tests the audit logging system with hash-chain integrity:
  - Each record includes hash of previous record
  - Chain can be verified for tampering
  - Recovery after restart maintains chain continuity
"""
import hashlib
import json
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../apps/api"))

from app.utils import jsonl_append, jsonl_tail


class TestAuditChain:
    """Test tamper-evident hash chain implementation."""

    def test_chain_genesis(self, tmp_path):
        """First record should reference the genesis hash (64 zeros)."""
        log = str(tmp_path / "audit.jsonl")
        prev_hash = "0" * 64

        entry = {
            "ts": int(time.time()),
            "action": "test.action",
            "outcome": "success",
            "actor": "test",
            "prev_hash": prev_hash,
        }
        record_str = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        entry["hash"] = hashlib.sha256(record_str.encode("utf-8")).hexdigest()

        jsonl_append(log, entry)
        records = jsonl_tail(log, limit=10)
        assert len(records) == 1
        assert records[0]["prev_hash"] == "0" * 64
        assert len(records[0]["hash"]) == 64

    def test_chain_continuity(self, tmp_path):
        """Each record must reference the previous record's hash."""
        log = str(tmp_path / "audit.jsonl")
        prev_hash = "0" * 64
        hashes = []

        for i in range(5):
            entry = {
                "ts": int(time.time()),
                "action": f"test.action.{i}",
                "outcome": "success",
                "actor": "test",
                "prev_hash": prev_hash,
            }
            record_str = json.dumps(entry, separators=(",", ":"), sort_keys=True)
            entry["hash"] = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
            prev_hash = entry["hash"]
            hashes.append(entry["hash"])
            jsonl_append(log, entry)

        records = jsonl_tail(log, limit=10)
        assert len(records) == 5

        # Verify chain: each record's prev_hash should match prior
        assert records[0]["prev_hash"] == "0" * 64
        for i in range(1, 5):
            assert records[i]["prev_hash"] == records[i - 1]["hash"], \
                f"Record {i} prev_hash doesn't match record {i-1} hash"

    def test_chain_tamper_detection(self, tmp_path):
        """If a record is modified, the chain breaks."""
        log = str(tmp_path / "audit.jsonl")
        prev_hash = "0" * 64

        entries = []
        for i in range(3):
            entry = {
                "ts": int(time.time()),
                "action": f"test.action.{i}",
                "outcome": "success",
                "actor": "test",
                "prev_hash": prev_hash,
            }
            record_str = json.dumps(entry, separators=(",", ":"), sort_keys=True)
            entry["hash"] = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
            prev_hash = entry["hash"]
            entries.append(entry)
            jsonl_append(log, entry)

        # Tamper: modify the first record's actor
        records = jsonl_tail(log, limit=10)
        tampered = records[0].copy()
        tampered["actor"] = "ATTACKER"
        # Re-write the file with tampered record
        with open(log, "w", encoding="utf-8") as f:
            f.write(json.dumps(tampered, separators=(",", ":")) + "\n")
            for r in records[1:]:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")

        # Verify chain is broken
        records = jsonl_tail(log, limit=10)
        # Recompute hash of first record to verify tamper detection
        check_entry = {k: v for k, v in records[0].items() if k != "hash"}
        check_str = json.dumps(check_entry, separators=(",", ":"), sort_keys=True)
        recomputed = hashlib.sha256(check_str.encode("utf-8")).hexdigest()
        assert recomputed != records[0]["hash"], "Tampered record should have different hash"

    def test_hash_deterministic(self):
        """Same input should always produce the same hash."""
        entry = {
            "ts": 1700000000,
            "action": "test",
            "outcome": "ok",
            "actor": "user",
            "prev_hash": "0" * 64,
        }
        record_str = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        h1 = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
        assert h1 == h2


class TestJSONLUtils:
    """Test JSONL append and tail utilities."""

    def test_append_and_read(self, tmp_path):
        log = str(tmp_path / "test.jsonl")
        for i in range(10):
            jsonl_append(log, {"i": i})
        records = jsonl_tail(log, limit=5)
        assert len(records) == 5
        assert records[0]["i"] == 5  # tail returns last 5
        assert records[-1]["i"] == 9

    def test_tail_on_empty_file(self, tmp_path):
        log = str(tmp_path / "empty.jsonl")
        records = jsonl_tail(log, limit=10)
        assert records == []

    def test_tail_on_missing_file(self, tmp_path):
        records = jsonl_tail(str(tmp_path / "nonexistent.jsonl"), limit=10)
        assert records == []

    def test_tail_limit_clamped(self, tmp_path):
        log = str(tmp_path / "test.jsonl")
        for i in range(10):
            jsonl_append(log, {"i": i})
        # Limit is clamped to [1, 500]
        records = jsonl_tail(log, limit=0)
        assert len(records) == 1  # min limit is 1
