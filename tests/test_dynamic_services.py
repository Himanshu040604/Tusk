"""Tests for dynamic service prefix resolution.

Covers the three-layer resolution:
  Layer 1: data/known_services.json (loaded at import time)
  Layer 2: _HARDCODED_SERVICES in constants.py (safety net fallback)
  Layer 3: DB service prefixes (merged at PolicyParser.__init__)
Also covers export_services_json() and the export-services CLI subcommand.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.sentinel.constants import (
    KNOWN_SERVICES,
    _HARDCODED_SERVICES,
    load_known_services,
)
from src.sentinel.parser import PolicyParser
from src.sentinel.database import Database, Service
from src.sentinel.cli import (
    build_parser,
    export_services_json,
    cmd_export_services,
    cmd_refresh,
)
from src.sentinel.constants import EXIT_SUCCESS, EXIT_IO_ERROR


# -----------------------------------------------------------------------
# TestLoadKnownServices -- Layer 1 & 2
# -----------------------------------------------------------------------


class TestLoadKnownServices:
    """Test the JSON loading and hardcoded fallback logic."""

    def test_known_services_is_a_set(self):
        assert isinstance(KNOWN_SERVICES, set)
        assert len(KNOWN_SERVICES) > 140

    def test_hardcoded_services_exists(self):
        assert isinstance(_HARDCODED_SERVICES, set)
        assert len(_HARDCODED_SERVICES) > 140

    def test_known_services_matches_hardcoded(self):
        # When JSON is in sync with hardcoded, they should be equal
        assert "s3" in KNOWN_SERVICES
        assert "ec2" in KNOWN_SERVICES
        assert "iam" in KNOWN_SERVICES

    def test_load_from_json(self, tmp_path: Path):
        json_file = tmp_path / "known_services.json"
        json_file.write_text(json.dumps({
            "_generated": "2026-01-01T00:00:00Z",
            "_source": "test",
            "services": ["s3", "ec2", "lambda", "custom-svc"],
        }), encoding="utf-8")

        result = load_known_services(json_path=json_file)
        assert result == {"s3", "ec2", "lambda", "custom-svc"}

    def test_fallback_on_missing_json(self):
        result = load_known_services(
            json_path=Path("/nonexistent/path/known_services.json")
        )
        assert result == _HARDCODED_SERVICES

    def test_fallback_on_corrupted_json(self, tmp_path: Path):
        bad = tmp_path / "known_services.json"
        bad.write_text("not valid json {{{", encoding="utf-8")

        result = load_known_services(json_path=bad)
        assert result == _HARDCODED_SERVICES

    def test_fallback_on_empty_services_array(self, tmp_path: Path):
        empty = tmp_path / "known_services.json"
        empty.write_text(json.dumps({
            "_generated": "2026-01-01T00:00:00Z",
            "_source": "test",
            "services": [],
        }), encoding="utf-8")

        result = load_known_services(json_path=empty)
        assert result == _HARDCODED_SERVICES

    def test_fallback_on_missing_services_key(self, tmp_path: Path):
        no_key = tmp_path / "known_services.json"
        no_key.write_text(json.dumps({
            "_generated": "2026-01-01T00:00:00Z",
        }), encoding="utf-8")

        result = load_known_services(json_path=no_key)
        assert result == _HARDCODED_SERVICES

    def test_load_returns_new_set_each_time(self, tmp_path: Path):
        json_file = tmp_path / "known_services.json"
        json_file.write_text(json.dumps({
            "_generated": "2026-01-01T00:00:00Z",
            "_source": "test",
            "services": ["s3", "ec2"],
        }), encoding="utf-8")

        result1 = load_known_services(json_path=json_file)
        result2 = load_known_services(json_path=json_file)
        assert result1 == result2
        assert result1 is not result2  # Different set objects


# -----------------------------------------------------------------------
# TestParserInitMerge -- Layer 3
# -----------------------------------------------------------------------


class TestParserInitMerge:
    """Test DB service merge at PolicyParser init."""

    def test_init_without_db(self):
        parser = PolicyParser()
        assert isinstance(parser.known_services, set)
        assert "s3" in parser.known_services
        assert "ec2" in parser.known_services

    def test_init_with_db_merges_services(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="custom-new-svc", service_name="Custom"))
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))

        parser = PolicyParser(db)

        # Should have both hardcoded/JSON services AND db services
        assert "s3" in parser.known_services
        assert "custom-new-svc" in parser.known_services
        # DB can grow the set, never shrink it
        assert len(parser.known_services) >= len(KNOWN_SERVICES)

    def test_db_only_adds_never_shrinks(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        # DB has only 1 service, but parser should still have all hardcoded
        db.insert_service(Service(service_prefix="new-svc", service_name="New"))

        parser = PolicyParser(db)
        assert "new-svc" in parser.known_services
        assert "s3" in parser.known_services  # Still has hardcoded services
        assert len(parser.known_services) == len(KNOWN_SERVICES) + 1

    def test_init_db_query_failure_no_crash(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        # Don't create schema -- querying will fail
        parser = PolicyParser(db)
        # Should not crash, falls back to JSON/hardcoded
        assert isinstance(parser.known_services, set)
        assert parser.known_services == KNOWN_SERVICES

    def test_each_parser_gets_independent_copy(self, tmp_path: Path):
        parser1 = PolicyParser()
        parser2 = PolicyParser()
        assert parser1.known_services == parser2.known_services
        assert parser1.known_services is not parser2.known_services

    def test_parser_validates_db_service_as_known(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="custom-svc", service_name="Custom"))

        parser = PolicyParser(db)
        # custom-svc should now be in known_services
        assert "custom-svc" in parser.known_services


# -----------------------------------------------------------------------
# TestExportServicesJson
# -----------------------------------------------------------------------


class TestExportServicesJson:
    """Test the export utility function."""

    def test_export_writes_correct_structure(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))
        db.insert_service(Service(service_prefix="ec2", service_name="Amazon EC2"))
        db.insert_service(Service(service_prefix="lambda", service_name="AWS Lambda"))

        output_file = tmp_path / "known_services.json"
        export_services_json(db, output_file)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "_generated" in data
        assert "_source" in data
        assert data["services"] == ["ec2", "lambda", "s3"]  # sorted

    def test_export_source_contains_db_path(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))

        output_file = tmp_path / "known_services.json"
        export_services_json(db, output_file)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "test.db" in data["_source"]

    def test_export_empty_db(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()

        output_file = tmp_path / "known_services.json"
        export_services_json(db, output_file)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["services"] == []

    def test_export_creates_parent_dirs(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))

        output_file = tmp_path / "nested" / "dir" / "known_services.json"
        export_services_json(db, output_file)

        assert output_file.exists()
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["services"] == ["s3"]

    def test_export_generated_timestamp_format(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()

        output_file = tmp_path / "known_services.json"
        export_services_json(db, output_file)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        # Should be ISO format: YYYY-MM-DDTHH:MM:SSZ
        assert data["_generated"].endswith("Z")
        assert "T" in data["_generated"]


# -----------------------------------------------------------------------
# TestCmdExportServices
# -----------------------------------------------------------------------


class TestCmdExportServices:
    """Test the export-services CLI subcommand."""

    def test_subcommand_registered(self):
        parser = build_parser()
        args = parser.parse_args(["export-services", "-d", "test.db"])
        assert args.command == "export-services"
        assert args.database == "test.db"

    def test_export_services_with_valid_db(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))

        output_file = tmp_path / "output.json"

        parser = build_parser()
        args = parser.parse_args([
            "export-services",
            "-d", str(tmp_path / "test.db"),
            "--export-output", str(output_file),
        ])
        exit_code = cmd_export_services(args)

        assert exit_code == EXIT_SUCCESS
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "s3" in data["services"]

    def test_export_services_no_db(self, tmp_path: Path):
        parser = build_parser()
        args = parser.parse_args([
            "export-services",
            "-d", str(tmp_path / "nonexistent.db"),
        ])
        exit_code = cmd_export_services(args)
        assert exit_code == EXIT_IO_ERROR


# -----------------------------------------------------------------------
# TestRefreshAutoExport
# -----------------------------------------------------------------------


class TestRefreshAutoExport:
    """Test that refresh auto-exports known_services.json."""

    def test_refresh_calls_auto_export(self, tmp_path: Path):
        sample = {
            "prefix": "s3",
            "service_name": "Amazon S3",
            "privileges": [
                {"privilege": "GetObject", "access_level": "Read"},
            ],
            "resources": [],
            "conditions": [],
        }
        data_file = tmp_path / "s3.json"
        data_file.write_text(json.dumps(sample), encoding="utf-8")

        db_path = tmp_path / "test.db"

        parser = build_parser()
        args = parser.parse_args([
            "refresh",
            "--source", "policy-sentry",
            "--data-path", str(data_file),
            "-d", str(db_path),
        ])

        with patch("src.sentinel.cli.export_services_json") as mock_export:
            mock_export.return_value = Path("data/known_services.json")
            exit_code = cmd_refresh(args)

        assert exit_code == EXIT_SUCCESS
        mock_export.assert_called_once()

    def test_refresh_dry_run_does_not_export(self, tmp_path: Path):
        sample = {
            "prefix": "s3",
            "service_name": "Amazon S3",
            "privileges": [
                {"privilege": "GetObject", "access_level": "Read"},
            ],
            "resources": [],
            "conditions": [],
        }
        data_file = tmp_path / "s3.json"
        data_file.write_text(json.dumps(sample), encoding="utf-8")

        db_path = tmp_path / "test.db"

        parser = build_parser()
        args = parser.parse_args([
            "refresh",
            "--source", "policy-sentry",
            "--data-path", str(data_file),
            "-d", str(db_path),
            "--dry-run",
        ])

        with patch("src.sentinel.cli.export_services_json") as mock_export:
            exit_code = cmd_refresh(args)

        assert exit_code == EXIT_SUCCESS
        mock_export.assert_not_called()
