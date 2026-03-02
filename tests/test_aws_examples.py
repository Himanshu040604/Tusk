"""Tests for the AWS examples fetcher, normalizer, and benchmark module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import base64

import pytest

from src.refresh.aws_examples import (
    RepoConfig,
    NormalizedPolicy,
    BenchmarkEntry,
    ExampleFetcher,
    PolicyNormalizer,
    BenchmarkRunner,
    BenchmarkReporter,
    DEFAULT_REPOS,
    verify_gh_cli,
    run_gh_api,
    is_iam_policy,
    infer_category,
    infer_policy_type,
    write_manifest,
    format_pct,
)


# ---------------------------------------------------------------------------
# Sample policy fixtures
# ---------------------------------------------------------------------------

VALID_SCP = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {"aws:RequestedRegion": "us-east-1"}
            },
        }
    ],
}

VALID_IDENTITY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

NOT_A_POLICY = {"name": "some-package", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    """Tests for module-level helper functions."""

    def test_is_iam_policy_valid(self) -> None:
        assert is_iam_policy(VALID_SCP) is True

    def test_is_iam_policy_missing_version(self) -> None:
        assert is_iam_policy({"Statement": []}) is False

    def test_is_iam_policy_missing_statement(self) -> None:
        assert is_iam_policy({"Version": "2012-10-17"}) is False

    def test_is_iam_policy_not_dict(self) -> None:
        assert is_iam_policy([1, 2, 3]) is False
        assert is_iam_policy("string") is False

    def test_infer_category_from_path(self) -> None:
        assert infer_category("repo/Region-controls/file.json") == "region-controls"

    def test_infer_category_uncategorized(self) -> None:
        assert infer_category("file.json") == "uncategorized"

    def test_infer_policy_type_scp_from_path(self) -> None:
        assert infer_policy_type("scp/deny.json", VALID_SCP) == "scp"

    def test_infer_policy_type_rcp(self) -> None:
        assert infer_policy_type("resource_control/p.json", VALID_SCP) == "rcp"

    def test_infer_policy_type_vpc_endpoint(self) -> None:
        assert infer_policy_type("vpc_endpoint/s3.json", VALID_SCP) == "vpc_endpoint"

    def test_infer_policy_type_boundary(self) -> None:
        assert infer_policy_type("permissions-boundary/pb.json", VALID_IDENTITY) == "boundary"

    def test_infer_policy_type_identity_default(self) -> None:
        assert infer_policy_type("policies/allow.json", VALID_IDENTITY) == "identity"

    def test_infer_policy_type_deny_heuristic(self) -> None:
        assert infer_policy_type("policies/deny.json", VALID_SCP) == "scp"

    def test_format_pct_normal(self) -> None:
        assert format_pct(25, 100) == "25.0%"

    def test_format_pct_zero_total(self) -> None:
        assert format_pct(0, 0) == "0.0%"


# ---------------------------------------------------------------------------
# verify_gh_cli tests
# ---------------------------------------------------------------------------

class TestVerifyGhCli:
    """Tests for gh CLI verification."""

    @patch("src.refresh.aws_examples.subprocess.run")
    def test_gh_authenticated(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        verify_gh_cli()

    @patch("src.refresh.aws_examples.subprocess.run")
    def test_gh_not_authenticated(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1)
        with pytest.raises(RuntimeError, match="not authenticated"):
            verify_gh_cli()

    @patch("src.refresh.aws_examples.subprocess.run", side_effect=FileNotFoundError)
    def test_gh_not_installed(self, mock_run: MagicMock) -> None:
        with pytest.raises(RuntimeError, match="not found"):
            verify_gh_cli()


# ---------------------------------------------------------------------------
# run_gh_api tests
# ---------------------------------------------------------------------------

class TestRunGhApi:
    """Tests for the gh API wrapper."""

    @patch("src.refresh.aws_examples.subprocess.run")
    def test_successful_call(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"key": "value"}'
        )
        result = run_gh_api("repos/owner/repo")
        assert result == {"key": "value"}

    @patch("src.refresh.aws_examples.subprocess.run")
    def test_with_params(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout='{"ok": true}'
        )
        result = run_gh_api("endpoint", params="recursive=1")
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "endpoint?recursive=1" in call_args[-1]
        assert result == {"ok": True}

    @patch("src.refresh.aws_examples.subprocess.run")
    def test_nonzero_exit(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert run_gh_api("bad/endpoint") is None

    @patch("src.refresh.aws_examples.subprocess.run", side_effect=OSError)
    def test_os_error(self, mock_run: MagicMock) -> None:
        assert run_gh_api("any") is None


# ---------------------------------------------------------------------------
# ExampleFetcher tests
# ---------------------------------------------------------------------------

class TestExampleFetcher:
    """Tests for the ExampleFetcher class."""

    @patch("src.refresh.aws_examples.verify_gh_cli")
    def test_init_calls_verify(self, mock_verify: MagicMock, tmp_path: Path) -> None:
        ExampleFetcher(tmp_path)
        mock_verify.assert_called_once()

    @patch("src.refresh.aws_examples.run_gh_api")
    @patch("src.refresh.aws_examples.verify_gh_cli")
    def test_fetch_repo_downloads_json(
        self, mock_verify: MagicMock, mock_api: MagicMock, tmp_path: Path
    ) -> None:
        tree_response = {
            "tree": [
                {"path": "policies/allow.json", "type": "blob"},
                {"path": "README.md", "type": "blob"},
                {"path": "package.json", "type": "blob"},
            ]
        }
        policy_b64 = base64.b64encode(
            json.dumps(VALID_IDENTITY).encode()
        ).decode()
        content_response = {"content": policy_b64}

        mock_api.side_effect = [tree_response, content_response]

        fetcher = ExampleFetcher(tmp_path)
        config = RepoConfig(owner="aws", repo="test", description="test")
        files = fetcher._fetch_repo(config)

        assert len(files) == 1
        assert files[0].name == "allow.json"
        data = json.loads(files[0].read_text(encoding="utf-8"))
        assert data["Version"] == "2012-10-17"

    @patch("src.refresh.aws_examples.run_gh_api", return_value=None)
    @patch("src.refresh.aws_examples.verify_gh_cli")
    def test_fetch_repo_handles_tree_failure(
        self, mock_verify: MagicMock, mock_api: MagicMock, tmp_path: Path
    ) -> None:
        fetcher = ExampleFetcher(tmp_path)
        config = RepoConfig(owner="aws", repo="bad", description="bad")
        assert fetcher._fetch_repo(config) == []

    @patch("src.refresh.aws_examples.run_gh_api")
    @patch("src.refresh.aws_examples.verify_gh_cli")
    def test_download_file_bad_base64(
        self, mock_verify: MagicMock, mock_api: MagicMock, tmp_path: Path
    ) -> None:
        mock_api.return_value = {"content": "not-valid-base64!!!"}
        config = RepoConfig(owner="aws", repo="test", description="t")
        result = ExampleFetcher._download_file(config, "file.json")
        assert result is None


# ---------------------------------------------------------------------------
# PolicyNormalizer tests
# ---------------------------------------------------------------------------

class TestPolicyNormalizer:
    """Tests for the PolicyNormalizer class."""

    def _create_file(self, base: Path, rel: str, data: dict) -> Path:
        """Helper to write a JSON file."""
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_normalizes_valid_policies(self, tmp_path: Path) -> None:
        raw = tmp_path / "raw"
        norm = tmp_path / "norm"
        self._create_file(raw, "repo/controls/deny.json", VALID_SCP)
        self._create_file(raw, "repo/policies/allow.json", VALID_IDENTITY)
        self._create_file(raw, "repo/package.json", NOT_A_POLICY)

        normalizer = PolicyNormalizer(raw, norm)
        policies = normalizer.normalize_all()

        assert len(policies) == 2
        assert (norm / "manifest.json").exists()

    def test_skips_non_policy_json(self, tmp_path: Path) -> None:
        raw = tmp_path / "raw"
        norm = tmp_path / "norm"
        self._create_file(raw, "repo/config.json", NOT_A_POLICY)

        normalizer = PolicyNormalizer(raw, norm)
        assert normalizer.normalize_all() == []

    def test_skips_invalid_json(self, tmp_path: Path) -> None:
        raw = tmp_path / "raw"
        norm = tmp_path / "norm"
        bad_file = raw / "repo" / "bad.json"
        bad_file.parent.mkdir(parents=True, exist_ok=True)
        bad_file.write_text("{invalid json", encoding="utf-8")

        normalizer = PolicyNormalizer(raw, norm)
        assert normalizer.normalize_all() == []

    def test_manifest_contains_metadata(self, tmp_path: Path) -> None:
        raw = tmp_path / "raw"
        norm = tmp_path / "norm"
        self._create_file(raw, "my-repo/category/policy.json", VALID_SCP)

        normalizer = PolicyNormalizer(raw, norm)
        normalizer.normalize_all()

        manifest = json.loads(
            (norm / "manifest.json").read_text(encoding="utf-8")
        )
        assert manifest["total_policies"] == 1
        assert "my-repo" in manifest["by_repo"]
        entry = manifest["policies"][0]
        assert entry["uses_conditions"] is True

    def test_detects_not_action(self, tmp_path: Path) -> None:
        raw = tmp_path / "raw"
        norm = tmp_path / "norm"
        policy_data = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "NotAction": ["s3:GetObject"],
                    "Resource": "*",
                }
            ],
        }
        self._create_file(raw, "repo/cat/not-action.json", policy_data)

        normalizer = PolicyNormalizer(raw, norm)
        policies = normalizer.normalize_all()

        assert len(policies) == 1
        assert policies[0].uses_not_action is True


# ---------------------------------------------------------------------------
# write_manifest tests
# ---------------------------------------------------------------------------

class TestWriteManifest:
    """Tests for the manifest writer."""

    def test_writes_valid_json(self, tmp_path: Path) -> None:
        policies = [
            NormalizedPolicy(
                source_repo="test-repo",
                relative_path="test-repo/cat/p.json",
                category="cat",
                policy_type="scp",
                local_path=tmp_path / "p.json",
                statement_count=2,
                uses_not_action=True,
                uses_conditions=False,
            )
        ]
        path = write_manifest(tmp_path, policies)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["total_policies"] == 1
        assert data["by_type"]["scp"] == 1


# ---------------------------------------------------------------------------
# BenchmarkRunner tests
# ---------------------------------------------------------------------------

class TestBenchmarkRunner:
    """Tests for the BenchmarkRunner class."""

    def test_run_single_success(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(
            json.dumps(VALID_IDENTITY), encoding="utf-8"
        )
        np = NormalizedPolicy(
            source_repo="test",
            relative_path="test/policy.json",
            category="test",
            policy_type="identity",
            local_path=policy_file,
        )
        runner = BenchmarkRunner()
        entry = runner._run_single(np)

        assert entry.success is True
        assert entry.verdict is not None
        total = entry.tier1_count + entry.tier2_count + entry.tier3_count
        assert total > 0

    def test_run_single_failure(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "bad.json"
        policy_file.write_text("{}", encoding="utf-8")
        np = NormalizedPolicy(
            source_repo="test",
            relative_path="test/bad.json",
            category="test",
            policy_type="identity",
            local_path=policy_file,
        )
        runner = BenchmarkRunner()
        entry = runner._run_single(np)

        assert entry.success is False
        assert entry.error is not None

    def test_run_benchmark_all(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(
            json.dumps(VALID_IDENTITY), encoding="utf-8"
        )
        policies = [
            NormalizedPolicy(
                source_repo="test",
                relative_path="test/p.json",
                category="cat",
                policy_type="identity",
                local_path=policy_file,
            )
        ]
        runner = BenchmarkRunner()
        entries = runner.run_benchmark(policies)
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# BenchmarkReporter tests
# ---------------------------------------------------------------------------

class TestBenchmarkReporter:
    """Tests for the BenchmarkReporter class."""

    def _make_entry(
        self,
        success: bool = True,
        t1: int = 5,
        t2: int = 1,
        t3: int = 0,
        verdict: str = "PASS",
    ) -> BenchmarkEntry:
        return BenchmarkEntry(
            policy_path="test.json",
            source_repo="repo",
            category="cat",
            success=success,
            tier1_count=t1,
            tier2_count=t2,
            tier3_count=t3,
            verdict=verdict if success else None,
            error=None if success else "parse error",
        )

    def test_generate_report_structure(self) -> None:
        entries = [self._make_entry(), self._make_entry(success=False)]
        reporter = BenchmarkReporter()
        report = reporter.generate_report(entries)

        assert report["summary"]["total_policies"] == 2
        assert report["summary"]["succeeded"] == 1
        assert report["summary"]["failed"] == 1
        assert report["tiers"]["tier1_valid"] == 5
        assert len(report["failures"]) == 1

    def test_tier_percentages(self) -> None:
        entries = [self._make_entry(t1=80, t2=15, t3=5)]
        reporter = BenchmarkReporter()
        report = reporter.generate_report(entries)

        assert report["tiers"]["tier1_pct"] == "80.0%"
        assert report["tiers"]["tier2_pct"] == "15.0%"
        assert report["tiers"]["tier3_pct"] == "5.0%"

    def test_format_text_output(self) -> None:
        entries = [self._make_entry()]
        reporter = BenchmarkReporter()
        report = reporter.generate_report(entries)
        text = reporter.format_text(report)

        assert "AWS Policy Benchmark Report" in text
        assert "Tier 1 (valid)" in text
        assert "PASS" in text

    def test_empty_entries(self) -> None:
        reporter = BenchmarkReporter()
        report = reporter.generate_report([])
        assert report["summary"]["total_policies"] == 0
        assert report["tiers"]["total_actions"] == 0


# ---------------------------------------------------------------------------
# RepoConfig tests
# ---------------------------------------------------------------------------

class TestRepoConfig:
    """Tests for the RepoConfig dataclass."""

    def test_full_name(self) -> None:
        config = RepoConfig(owner="aws", repo="test", description="t")
        assert config.full_name == "aws/test"

    def test_default_excludes(self) -> None:
        config = RepoConfig(owner="o", repo="r", description="d")
        assert "package.json" in config.exclude_files

    def test_default_repos_exist(self) -> None:
        assert len(DEFAULT_REPOS) == 3
        assert all(r.owner == "aws-samples" for r in DEFAULT_REPOS)
