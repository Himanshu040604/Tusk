"""Tests for the CLI module and output formatters."""

import json
import sys
from argparse import Namespace
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from src.sentinel.cli import (
    build_parser,
    read_policy_input,
    cmd_validate,
    cmd_analyze,
    cmd_rewrite,
    cmd_run,
    cmd_info,
    resolve_database,
    resolve_inventory,
)
from src.sentinel.exit_codes import (
    EXIT_SUCCESS,
    EXIT_ISSUES_FOUND,
    EXIT_INVALID_ARGS,
    EXIT_IO_ERROR,
    EXIT_CRITICAL_FINDING,
)
from src.sentinel.formatters import TextFormatter, JsonFormatter, MarkdownFormatter
from src.sentinel.database import Database, Service, Action
from src.sentinel.inventory import ResourceInventory
from src.sentinel.parser import (
    Policy,
    Statement,
    ValidationResult,
    ValidationTier,
)
from src.sentinel.analyzer import RiskFinding, RiskSeverity
from src.sentinel.rewriter import (
    PolicyRewriter,
    RewriteConfig,
    RewriteResult,
    RewriteChange,
)
from src.sentinel.self_check import (
    PipelineResult,
    SelfCheckResult,
    CheckVerdict,
    CheckSeverity,
    CheckFinding,
    PipelineConfig,
)


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

VALID_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }
)

WILDCARD_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
)


@pytest.fixture
def tmp_policy_file(tmp_path: Path) -> Path:
    """Write a valid policy JSON to a temp file."""
    p = tmp_path / "policy.json"
    p.write_text(VALID_POLICY, encoding="utf-8")
    return p


@pytest.fixture
def tmp_wildcard_policy(tmp_path: Path) -> Path:
    """Write a wildcard policy JSON to a temp file."""
    p = tmp_path / "wildcard.json"
    p.write_text(WILDCARD_POLICY, encoding="utf-8")
    return p


@pytest.fixture
def cli_db_path(tmp_path: Path, migrated_db_template: Path) -> str:
    """v0.7.0 (Phase 7.3) — per-test DB path string for cmd_* handlers.

    Returns the string path of a template-backed DB that's safe to pass
    as ``database=`` on ``argparse.Namespace`` constructs used to drive
    ``cmd_run``/``cmd_analyze``/``cmd_rewrite`` in isolation.  Previously
    these tests relied on ``database=None`` which fell back to the shared
    ``data/iam_actions.db`` at repo root — a shared-state source of
    the v0.6.2 serial-mode HMAC failures.
    """
    from tests.conftest import make_test_db

    return str(make_test_db(tmp_path, template=migrated_db_template))


@pytest.fixture
def fresh_db(tmp_path: Path) -> Database:
    """Create a fresh database with schema."""
    db = Database(tmp_path / "test.db")
    db.create_schema()
    db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))
    db.insert_action(
        Action(
            action_id=None,
            service_prefix="s3",
            action_name="GetObject",
            full_action="s3:GetObject",
            description="Read object",
            access_level="Read",
            is_read=True,
        )
    )
    return db


@pytest.fixture
def fresh_inv(tmp_path: Path) -> ResourceInventory:
    """Create a fresh resource inventory with schema."""
    inv = ResourceInventory(tmp_path / "inventory.db")
    inv.create_schema()
    return inv


# -----------------------------------------------------------------------
# TestBuildParser
# -----------------------------------------------------------------------


class TestBuildParser:
    """Test argument parser construction."""

    def test_creates_parser(self):
        p = build_parser()
        assert p is not None

    def test_validate_subcommand(self):
        p = build_parser()
        args = p.parse_args(["validate", "policy.json"])
        assert args.command == "validate"
        assert args.policy_file == "policy.json"

    def test_analyze_subcommand(self):
        p = build_parser()
        args = p.parse_args(["analyze", "policy.json", "--intent", "read-only s3"])
        assert args.command == "analyze"
        assert args.intent == "read-only s3"

    def test_rewrite_subcommand(self):
        p = build_parser()
        args = p.parse_args(
            [
                "rewrite",
                "policy.json",
                "--intent",
                "read-only",
                "--account-id",
                "111111111111",
                "--region",
                "us-west-2",
                "--no-companions",
                "--no-conditions",
            ]
        )
        assert args.command == "rewrite"
        assert args.no_companions is True
        assert args.no_conditions is True
        assert args.account_id == "111111111111"

    def test_run_subcommand(self):
        p = build_parser()
        args = p.parse_args(
            [
                "run",
                "policy.json",
                "--strict",
                "--max-retries",
                "5",
            ]
        )
        assert args.command == "run"
        assert args.strict is True
        assert args.max_retries == 5

    def test_refresh_subcommand(self):
        p = build_parser()
        args = p.parse_args(
            [
                "refresh",
                "--source",
                "policy-sentry",
                "--data-path",
                "/data",
                "--dry-run",
            ]
        )
        assert args.command == "refresh"
        assert args.source == "policy-sentry"
        assert args.dry_run is True

    def test_info_subcommand(self):
        p = build_parser()
        args = p.parse_args(["info"])
        assert args.command == "info"

    def test_shared_flags(self):
        p = build_parser()
        args = p.parse_args(
            [
                "validate",
                "policy.json",
                "-d",
                "mydb.db",
                "-i",
                "inv.db",
                "-f",
                "json",
                "-o",
                "out.json",
            ]
        )
        assert args.database == "mydb.db"
        assert args.inventory == "inv.db"
        assert args.output_format == "json"
        assert args.output == "out.json"

    def test_stdin_marker(self):
        p = build_parser()
        args = p.parse_args(["validate", "-"])
        assert args.policy_file == "-"

    def test_version_flag(self):
        p = build_parser()
        args = p.parse_args(["--version"])
        assert args.version is True

    def test_default_output_format(self):
        p = build_parser()
        args = p.parse_args(["validate", "policy.json"])
        assert args.output_format == "text"


# -----------------------------------------------------------------------
# TestReadPolicyInput
# -----------------------------------------------------------------------


class TestReadPolicyInput:
    """Test policy file reading."""

    def test_read_from_file(self, tmp_policy_file: Path):
        content, fmt = read_policy_input(str(tmp_policy_file))
        assert '"Version"' in content
        assert fmt == "json"

    def test_read_from_stdin(self):
        with patch("sys.stdin", StringIO(VALID_POLICY)):
            content, fmt = read_policy_input("-")
            assert '"Version"' in content
            assert fmt == "json"

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            read_policy_input("/nonexistent/policy.json")


# -----------------------------------------------------------------------
# TestCmdValidate
# -----------------------------------------------------------------------


class TestCmdValidate:
    """Test the validate subcommand handler."""

    def test_valid_policy_returns_success(self, tmp_policy_file: Path, fresh_db: Database):
        args = Namespace(
            policy_file=str(tmp_policy_file),
            database=str(fresh_db.db_path),
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
        )
        code = cmd_validate(args)
        assert code == EXIT_SUCCESS

    def test_invalid_json_returns_invalid_args(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        args = Namespace(
            policy_file=str(bad),
            database=None,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
        )
        code = cmd_validate(args)
        assert code == EXIT_INVALID_ARGS

    def test_missing_file_returns_io_error(self):
        args = Namespace(
            policy_file="/does/not/exist.json",
            database=None,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
        )
        code = cmd_validate(args)
        assert code == EXIT_IO_ERROR

    def test_json_format(self, tmp_policy_file: Path, tmp_path: Path):
        out_file = tmp_path / "out.json"
        args = Namespace(
            policy_file=str(tmp_policy_file),
            database=None,
            inventory=None,
            output_format="json",
            output=str(out_file),
            input_format="auto",
        )
        code = cmd_validate(args)
        assert code == EXIT_SUCCESS
        result = json.loads(out_file.read_text())
        assert "results" in result


# -----------------------------------------------------------------------
# TestCmdRun
# -----------------------------------------------------------------------


class TestCmdRun:
    """Test the run subcommand handler."""

    def test_run_pipeline_returns_exit_code(self, tmp_policy_file: Path, cli_db_path: str):
        args = Namespace(
            policy_file=str(tmp_policy_file),
            database=cli_db_path,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
            intent=None,
            account_id=None,
            region=None,
            strict=False,
            max_retries=3,
            no_companions=False,
            no_conditions=False,
            interactive=False,
        )
        code = cmd_run(args)
        # Without DB, self-check may find warnings
        assert code in (EXIT_SUCCESS, EXIT_ISSUES_FOUND)

    def test_run_pipeline_with_intent(self, tmp_policy_file: Path, cli_db_path: str):
        args = Namespace(
            policy_file=str(tmp_policy_file),
            database=cli_db_path,
            inventory=None,
            output_format="json",
            output=None,
            input_format="auto",
            intent="read-only s3",
            account_id=None,
            region=None,
            strict=False,
            max_retries=3,
            no_companions=False,
            no_conditions=False,
            interactive=False,
        )
        code = cmd_run(args)
        assert code in (EXIT_SUCCESS, EXIT_ISSUES_FOUND)

    def test_run_strict_mode(self, tmp_wildcard_policy: Path, cli_db_path: str):
        args = Namespace(
            policy_file=str(tmp_wildcard_policy),
            database=cli_db_path,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
            intent=None,
            account_id=None,
            region=None,
            strict=True,
            max_retries=1,
            no_companions=False,
            no_conditions=False,
            interactive=False,
        )
        code = cmd_run(args)
        # Strict mode with wildcard should fail.  Wildcard-all is a CRITICAL
        # finding post-Phase 2 (see cli._verdict_to_exit_code) so it exits
        # with EXIT_CRITICAL_FINDING (4) rather than EXIT_ISSUES_FOUND (1).
        assert code in (EXIT_ISSUES_FOUND, EXIT_CRITICAL_FINDING)

    def test_run_invalid_json(self, tmp_path: Path, cli_db_path: str):
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        args = Namespace(
            policy_file=str(bad),
            database=cli_db_path,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
            intent=None,
            account_id=None,
            region=None,
            strict=False,
            max_retries=3,
            no_companions=False,
            no_conditions=False,
            interactive=False,
        )
        code = cmd_run(args)
        assert code == EXIT_INVALID_ARGS


# -----------------------------------------------------------------------
# TestCmdInfo
# -----------------------------------------------------------------------


class TestCmdInfo:
    """Test the info subcommand handler."""

    def test_info_with_db(self, fresh_db: Database):
        args = Namespace(
            database=str(fresh_db.db_path),
            inventory=None,
            output_format="text",
            output=None,
        )
        code = cmd_info(args)
        assert code == EXIT_SUCCESS

    def test_info_no_db(self):
        args = Namespace(
            database="/nonexistent.db",
            inventory=None,
            output_format="text",
            output=None,
        )
        code = cmd_info(args)
        assert code == EXIT_IO_ERROR

    def test_info_json_format(self, fresh_db: Database, tmp_path: Path):
        out_file = tmp_path / "info.json"
        args = Namespace(
            database=str(fresh_db.db_path),
            inventory=None,
            output_format="json",
            output=str(out_file),
        )
        code = cmd_info(args)
        assert code == EXIT_SUCCESS
        result = json.loads(out_file.read_text())
        assert result["service_count"] == 1
        assert result["action_count"] == 1


# -----------------------------------------------------------------------
# TestOutputFormats
# -----------------------------------------------------------------------


class TestOutputFormats:
    """Test the three formatter classes produce valid output."""

    @pytest.fixture
    def sample_validation_results(self):
        return [
            ValidationResult(
                action="s3:GetObject",
                tier=ValidationTier.TIER_1_VALID,
                reason="Action found in IAM database",
                access_level="Read",
            ),
            ValidationResult(
                action="s3:FakeAction",
                tier=ValidationTier.TIER_3_INVALID,
                reason="Unknown action",
            ),
        ]

    @pytest.fixture
    def sample_policy(self):
        return Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )

    @pytest.fixture
    def sample_risk_findings(self):
        return [
            RiskFinding(
                risk_type="WILDCARD_ALL_ACTIONS",
                severity=RiskSeverity.CRITICAL,
                action="*",
                description="Full wildcard grants ALL permissions",
                remediation="Replace with specific actions",
            ),
        ]

    @pytest.fixture
    def sample_rewrite_result(self, sample_policy):
        return RewriteResult(
            original_policy=sample_policy,
            rewritten_policy=sample_policy,
            changes=[
                RewriteChange(
                    change_type="WILDCARD_REPLACED",
                    description="Replaced wildcard",
                    original_value="*",
                    new_value="s3:GetObject",
                ),
            ],
            assumptions=["No database available"],
            warnings=["Manual review needed"],
        )

    def test_text_validation(self, sample_validation_results, sample_policy):
        fmt = TextFormatter()
        output = fmt.format_validation(sample_validation_results, sample_policy)
        assert "[VALID]" in output
        assert "[INVALID]" in output
        assert "s3:GetObject" in output

    def test_json_validation(self, sample_validation_results, sample_policy):
        fmt = JsonFormatter()
        output = fmt.format_validation(sample_validation_results, sample_policy)
        data = json.loads(output)
        assert data["version"] == "2012-10-17"
        assert len(data["results"]) == 2

    def test_markdown_validation(self, sample_validation_results, sample_policy):
        fmt = MarkdownFormatter()
        output = fmt.format_validation(sample_validation_results, sample_policy)
        assert "# Policy Validation Results" in output
        assert "| `s3:GetObject`" in output

    def test_text_risk_findings(self, sample_risk_findings):
        fmt = TextFormatter()
        output = fmt.format_risk_findings(sample_risk_findings)
        assert "[CRITICAL]" in output
        assert "WILDCARD_ALL_ACTIONS" in output

    def test_json_risk_findings(self, sample_risk_findings):
        fmt = JsonFormatter()
        output = fmt.format_risk_findings(sample_risk_findings)
        data = json.loads(output)
        assert data["total_findings"] == 1

    def test_markdown_risk_findings(self, sample_risk_findings):
        fmt = MarkdownFormatter()
        output = fmt.format_risk_findings(sample_risk_findings)
        assert "# Risk Analysis" in output
        assert "CRITICAL" in output

    def test_text_rewrite_result(self, sample_rewrite_result):
        fmt = TextFormatter()
        output = fmt.format_rewrite_result(sample_rewrite_result)
        assert "Changes applied: 1" in output
        assert "WILDCARD_REPLACED" in output

    def test_json_rewrite_result(self, sample_rewrite_result):
        fmt = JsonFormatter()
        output = fmt.format_rewrite_result(sample_rewrite_result)
        data = json.loads(output)
        assert len(data["changes"]) == 1
        assert "rewritten_policy" in data

    def test_markdown_rewrite_result(self, sample_rewrite_result):
        fmt = MarkdownFormatter()
        output = fmt.format_rewrite_result(sample_rewrite_result)
        assert "# Rewrite Result" in output
        assert "```json" in output

    def test_text_no_findings(self):
        fmt = TextFormatter()
        output = fmt.format_risk_findings([])
        assert "No risk findings detected." in output

    def test_text_db_info(self):
        fmt = TextFormatter()
        output = fmt.format_db_info({"schema_version": "1.0"}, service_count=5, action_count=100)
        assert "Services: 5" in output
        assert "Actions:  100" in output

    def test_json_db_info(self):
        fmt = JsonFormatter()
        output = fmt.format_db_info({"schema_version": "1.0"}, service_count=5, action_count=100)
        data = json.loads(output)
        assert data["service_count"] == 5

    def test_markdown_db_info(self):
        fmt = MarkdownFormatter()
        output = fmt.format_db_info({"schema_version": "1.0"}, service_count=5, action_count=100)
        assert "# Database Info" in output
        assert "| schema_version | 1.0 |" in output


# -----------------------------------------------------------------------
# TestExitCodes
# -----------------------------------------------------------------------


class TestExitCodes:
    """Verify exit code constants."""

    def test_exit_success(self):
        assert EXIT_SUCCESS == 0

    def test_exit_issues_found(self):
        assert EXIT_ISSUES_FOUND == 1

    def test_exit_invalid_args(self):
        assert EXIT_INVALID_ARGS == 2

    def test_exit_io_error(self):
        assert EXIT_IO_ERROR == 3


# -----------------------------------------------------------------------
# TestResolveDatabase
# -----------------------------------------------------------------------


class TestResolveDatabase:
    """Test database resolution logic."""

    def test_explicit_path(self, fresh_db: Database):
        args = Namespace(database=str(fresh_db.db_path), inventory=None)
        db = resolve_database(args)
        assert db is not None

    def test_explicit_nonexistent(self):
        args = Namespace(database="/no/such/db.db", inventory=None)
        db = resolve_database(args)
        assert db is None

    def test_no_flag_no_default(self):
        args = Namespace(database=None, inventory=None)
        # May or may not find a DB depending on cwd -- just verify no crash
        resolve_database(args)


class TestResolveInventory:
    """Test inventory resolution logic."""

    def test_explicit_path(self, fresh_inv: ResourceInventory):
        args = Namespace(inventory=str(fresh_inv.db_path), database=None)
        inv = resolve_inventory(args)
        assert inv is not None

    def test_explicit_nonexistent(self):
        args = Namespace(inventory="/no/such/inv.db", database=None)
        inv = resolve_inventory(args)
        assert inv is None


# -----------------------------------------------------------------------
# TestCmdAnalyze
# -----------------------------------------------------------------------


class TestCmdAnalyze:
    """Test the analyze subcommand handler."""

    def test_analyze_policy_with_exfil_risk_exits_issues_found(
        self, tmp_policy_file: Path, cli_db_path: str
    ):
        """v0.6.2 split (was `test_analyze_returns_success_for_safe_policy`):
        strict assertion that s3:GetObject is classified as MEDIUM
        data_exfiltration and therefore returns EXIT_ISSUES_FOUND.

        The shipped tmp_policy_file fixture contains `s3:GetObject` which
        is a seeded exfiltration classification -- a rewrite that broke
        this classification would silently pass under the old
        `code in (SUCCESS, ISSUES_FOUND)` widened assertion.
        """
        args = Namespace(
            policy_file=str(tmp_policy_file),
            database=cli_db_path,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
            intent=None,
        )
        code = cmd_analyze(args)
        assert code == EXIT_ISSUES_FOUND, (
            f"Expected EXIT_ISSUES_FOUND ({EXIT_ISSUES_FOUND}) from "
            f"s3:GetObject exfil classification; got {code}."
        )

    def test_analyze_truly_safe_policy_exits_success(self, tmp_path: Path, cli_db_path: str):
        """v0.6.2 split: a policy containing only a List-tier action with
        no exfil/destruction/escalation classification must return
        EXIT_SUCCESS strictly.
        """
        # s3:ListBucket is a List-tier action, not a seeded dangerous
        # classification, and thus must not produce any findings.
        safe = tmp_path / "safe_policy.json"
        safe.write_text(
            json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:ListBucket",
                            "Resource": "arn:aws:s3:::my-bucket",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        args = Namespace(
            policy_file=str(safe),
            database=cli_db_path,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
            intent=None,
        )
        code = cmd_analyze(args)
        assert code == EXIT_SUCCESS, (
            f"Expected EXIT_SUCCESS ({EXIT_SUCCESS}) for safe policy; got {code}."
        )

    def test_analyze_wildcard_returns_issues(self, tmp_wildcard_policy: Path, cli_db_path: str):
        args = Namespace(
            policy_file=str(tmp_wildcard_policy),
            database=cli_db_path,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
            intent=None,
        )
        code = cmd_analyze(args)
        # Wildcard `*` is CRITICAL → EXIT_CRITICAL_FINDING (4).
        assert code in (EXIT_ISSUES_FOUND, EXIT_CRITICAL_FINDING)


# -----------------------------------------------------------------------
# TestCmdRewrite
# -----------------------------------------------------------------------


class TestCmdRewrite:
    """Test the rewrite subcommand handler."""

    def test_rewrite_returns_success(self, tmp_policy_file: Path, cli_db_path: str):
        args = Namespace(
            policy_file=str(tmp_policy_file),
            database=cli_db_path,
            inventory=None,
            output_format="text",
            output=None,
            input_format="auto",
            intent=None,
            account_id=None,
            region=None,
            no_companions=False,
            no_conditions=False,
        )
        code = cmd_rewrite(args)
        assert code == EXIT_SUCCESS

    def test_rewrite_json_output(self, tmp_policy_file: Path, tmp_path: Path, cli_db_path: str):
        out_file = tmp_path / "rewritten.json"
        args = Namespace(
            policy_file=str(tmp_policy_file),
            database=cli_db_path,
            inventory=None,
            output_format="json",
            output=str(out_file),
            input_format="auto",
            intent=None,
            account_id=None,
            region=None,
            no_companions=False,
            no_conditions=False,
        )
        code = cmd_rewrite(args)
        assert code == EXIT_SUCCESS
        data = json.loads(out_file.read_text())
        assert "rewritten_policy" in data


# -----------------------------------------------------------------------
# TestPipelineFormatters
# -----------------------------------------------------------------------


class TestPipelineFormatters:
    """Test formatting of pipeline results across all formatters."""

    @pytest.fixture
    def sample_pipeline_result(self):
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::my-bucket/*"],
                ),
            ],
        )
        rewrite_result = RewriteResult(
            original_policy=policy,
            rewritten_policy=policy,
        )
        sc_result = SelfCheckResult(
            verdict=CheckVerdict.PASS,
            findings=[],
            completeness_score=1.0,
            assumptions_valid=True,
            tier2_preserved_actions=[],
            summary="Self-check PASS",
        )
        return PipelineResult(
            original_policy=policy,
            rewritten_policy=policy,
            validation_results=[
                ValidationResult(
                    action="s3:GetObject",
                    tier=ValidationTier.TIER_1_VALID,
                    reason="Found",
                ),
            ],
            risk_findings=[],
            rewrite_result=rewrite_result,
            self_check_result=sc_result,
            iterations=1,
            final_verdict=CheckVerdict.PASS,
            pipeline_summary="Pipeline completed.",
        )

    def test_text_pipeline(self, sample_pipeline_result):
        fmt = TextFormatter()
        output = fmt.format_pipeline_result(sample_pipeline_result)
        assert "[PASS]" in output
        assert "Pipeline Result" in output

    def test_json_pipeline(self, sample_pipeline_result):
        fmt = JsonFormatter()
        output = fmt.format_pipeline_result(sample_pipeline_result)
        data = json.loads(output)
        assert data["final_verdict"] == "PASS"
        assert "rewritten_policy" in data

    def test_markdown_pipeline(self, sample_pipeline_result):
        fmt = MarkdownFormatter()
        output = fmt.format_pipeline_result(sample_pipeline_result)
        assert "# IAM Policy Sentinel" in output
        assert "PASS" in output


# -----------------------------------------------------------------------
# v0.8.1 (PE1): HMACError handling at CLI boundary
# -----------------------------------------------------------------------


class TestCLIHMACErrorHandling:
    """Outer main() must catch HMACError and emit actionable guidance."""

    def test_main_catches_hmac_error_with_recovery_message(self, capsys, monkeypatch, tmp_path):
        """HMACError raised by a handler => clean EXIT_IO_ERROR + message."""
        from src.sentinel.cli import main
        from src.sentinel.hmac_keys import HMACError

        def _fake_handler(args):
            raise HMACError("cache.key has broad world-permissions (0o777)")

        # Redirect main() to a fake handler that raises HMACError.
        monkeypatch.setattr("sys.argv", ["sentinel", "info"])
        monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
        # Bypass alembic/migration machinery and force dispatch to our handler
        monkeypatch.setattr("src.sentinel.cli._bootstrap_config_and_logging", lambda args: None)
        monkeypatch.setattr(
            "src.sentinel.cli.check_and_upgrade_all_dbs",
            lambda *a, **kw: None,
            raising=False,
        )
        # Patch the handlers dict at dispatch — since handlers is built
        # inside main(), monkey-patch the cmd_info global instead.
        monkeypatch.setattr("src.sentinel.cli.cmd_info", _fake_handler)

        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == EXIT_IO_ERROR
        captured = capsys.readouterr()
        assert "HMAC key failure" in captured.err
        assert "sentinel cache rotate-key" in captured.err

    def test_main_hmac_handler_source_grep(self):
        """Source contains the HMAC outer-handler pattern."""
        src_path = Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli.py"
        src = src_path.read_text(encoding="utf-8")
        assert "except HMACError as e:" in src, (
            "main() must catch HMACError at the outer handler dispatch"
        )
        assert "sentinel cache rotate-key" in src
        assert "from .hmac_keys import HMACError" in src


# -----------------------------------------------------------------------
# v0.8.1 (PE2): cmd_info and refresh exit-code propagation
# -----------------------------------------------------------------------


class TestCmdInfoAlembicProbe:
    """cmd_info alembic probe must propagate failures as EXIT_IO_ERROR."""

    def test_alembic_probe_failure_returns_io_error(self, capsys, monkeypatch, fresh_db):
        """When _current_revision raises, cmd_info returns EXIT_IO_ERROR."""
        args = Namespace(
            database=str(fresh_db.db_path),
            inventory=None,
            output_format="text",
            output=None,
        )

        def _raising_current_revision(db_path):
            raise RuntimeError("alembic_version query failed (simulated)")

        monkeypatch.setattr("src.sentinel.migrations._current_revision", _raising_current_revision)
        exit_code = cmd_info(args)
        assert exit_code == EXIT_IO_ERROR
        captured = capsys.readouterr()
        assert "Alembic revision probe failed" in captured.err
        # The alembic_revision field should still be rendered in the info block.
        assert "<error:" in captured.out

    def test_alembic_probe_none_returns_success(self, capsys, monkeypatch, fresh_db):
        """When _current_revision returns None (pre-Alembic DB), EXIT_SUCCESS."""
        args = Namespace(
            database=str(fresh_db.db_path),
            inventory=None,
            output_format="text",
            output=None,
        )

        monkeypatch.setattr("src.sentinel.migrations._current_revision", lambda _: None)
        exit_code = cmd_info(args)
        assert exit_code == EXIT_SUCCESS


class TestCmdRefreshStatsErrors:
    """cmd_refresh must propagate stats.errors as EXIT_IO_ERROR."""

    def test_refresh_with_errors_returns_io_error(self):
        """v0.8.1 (PE2) + H1: stats.errors non-empty => EXIT_IO_ERROR.

        Regression guard for three refresh exit paths:
          - cmd_refresh main (PE2, cli.py ~1313)
          - _cmd_refresh_new_source offline tail (H1, cli.py ~1384)
          - _refresh_live cloudsplaining (H1, cli.py ~1472)
        All must guard stats.errors with EXIT_IO_ERROR at variable indentation
        levels, so we match the 'if stats.errors:' + 'return EXIT_IO_ERROR'
        pair via regex and require at least two occurrences to cover sites
        added by H1 on top of the PE2 baseline.
        """
        import re as _re

        src_path = Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli.py"
        src = src_path.read_text(encoding="utf-8")
        pattern = _re.compile(
            r"if stats\.errors:\s+return EXIT_IO_ERROR",
            _re.MULTILINE,
        )
        occurrences = len(pattern.findall(src))
        assert occurrences >= 2, (
            f"Expected >=2 'if stats.errors: return EXIT_IO_ERROR' guards "
            f"in cli.py (PE2 + H1 on cloudsplaining); found {occurrences}"
        )

    def test_refresh_live_does_not_use_issues_found(self):
        """H1: _refresh_live must normalize on EXIT_IO_ERROR, not EXIT_ISSUES_FOUND.

        EXIT_ISSUES_FOUND is reserved for policy-audit findings, not IO /
        ingestion failures.  Per exit_codes.py docstrings, a partial-seed
        fetch failure is an IO error.
        """
        src_path = Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli.py"
        src = src_path.read_text(encoding="utf-8")
        # Slice out the _refresh_live function body.
        marker = "def _refresh_live("
        assert marker in src, "cli._refresh_live not found"
        after = src.split(marker, 1)[1]
        body = after.split("\ndef ", 1)[0]
        assert "EXIT_ISSUES_FOUND" not in body, (
            "H1 regression: _refresh_live must not use EXIT_ISSUES_FOUND; "
            "partial ingestion failures return EXIT_IO_ERROR (PE2 parity)."
        )


class TestRefreshLiveContextManager:
    """H2: _refresh_live must use `with` for the HTTP client in both branches.

    Regression guard for the UnboundLocalError masking bug: the bare
    ``client = _build_live_client()`` + ``finally: client.close()`` pattern
    raises UnboundLocalError when the constructor itself raises (HMACError,
    OSError), masking the real exception from main()'s outer handler.
    """

    def test_managed_policies_uses_context_manager(self):
        """Source-grep: managed-policies branch must wrap the client in `with`.

        This pins the fix so that a future refactor cannot silently
        reintroduce the bare-assignment pattern.
        """
        src_path = Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli.py"
        src = src_path.read_text(encoding="utf-8")
        marker = "def _refresh_live("
        body = src.split(marker, 1)[1].split("\ndef ", 1)[0]
        # Both managed-policies and cloudsplaining branches must use
        # `with _build_live_client() as client:` — two occurrences total.
        occurrences = body.count("with _build_live_client() as client:")
        assert occurrences >= 2, (
            f"Expected >=2 'with _build_live_client() as client:' in "
            f"_refresh_live (managed-policies + cloudsplaining); found "
            f"{occurrences}"
        )

    def test_managed_policies_build_client_raises_propagates(self, monkeypatch):
        """If _build_live_client() raises, the real exception propagates.

        Pre-H2: a ``finally: client.close()`` on an unbound ``client``
        raised UnboundLocalError, masking HMACError/OSError.
        Post-H2: ``with`` never enters __enter__ if the builder raises,
        so the original exception surfaces cleanly.
        """
        from src.sentinel.hmac_keys import HMACError
        import src.sentinel.cli as cli_mod

        def _raise_hmac():
            raise HMACError("simulated key-permission failure")

        monkeypatch.setattr(cli_mod, "_build_live_client", _raise_hmac)
        # db argument is unused before the raise, so None is safe.
        with pytest.raises(HMACError, match="simulated key-permission failure"):
            cli_mod._refresh_live(db=None, source="managed-policies")

    def test_managed_policies_closes_client_on_success(self, monkeypatch):
        """On success, the client's __exit__ is invoked (cleanup guaranteed)."""
        import src.sentinel.cli as cli_mod

        class _FakeClient:
            def __init__(self) -> None:
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                self.closed = True

            def close(self) -> None:
                self.closed = True

        fake = _FakeClient()
        monkeypatch.setattr(cli_mod, "_build_live_client", lambda: fake)

        class _NoOpScraper:
            def __init__(self, db, client) -> None:  # noqa: ARG002
                pass

            def scrape_one(self, *, name, arn, url):  # noqa: ARG002
                return "ADD"

        monkeypatch.setattr(
            "src.sentinel.refresh.aws_managed_policies.ManagedPoliciesLiveScraper",
            _NoOpScraper,
        )
        rc = cli_mod._refresh_live(db=None, source="managed-policies")
        assert rc == EXIT_SUCCESS
        assert fake.closed is True, (
            "H2: managed-policies branch must close the client via "
            "context-manager __exit__; client.closed was never set."
        )

    def test_cloudsplaining_live_returns_invalid_args(self, capsys):
        """PE9: --source cloudsplaining --live is deprecated.

        The previous implementation fetched a 404 URL (cloudsplaining
        never hosted iam_definition.json — it imports policy_sentry's
        at runtime).  The deprecation stub returns EXIT_INVALID_ARGS
        with an actionable pointer at ``--source policy-sentry --live``.
        """
        import src.sentinel.cli as cli_mod

        rc = cli_mod._refresh_live(db=None, source="cloudsplaining")
        assert rc == EXIT_INVALID_ARGS
        captured = capsys.readouterr()
        assert "policy-sentry --live" in captured.err, (
            "Deprecation message must point users at the working policy-sentry --live source."
        )

    def test_policy_sentry_live_build_client_raises_propagates(self, monkeypatch):
        """PE9: HMACError on _build_live_client surfaces cleanly.

        Mirrors the H2 regression test for managed-policies — confirms
        the new policy-sentry branch uses ``with _build_live_client()``
        and propagates constructor errors rather than UnboundLocalError.
        """
        from src.sentinel.hmac_keys import HMACError
        import src.sentinel.cli as cli_mod

        def _raise_hmac():
            raise HMACError("simulated key-permission failure")

        monkeypatch.setattr(cli_mod, "_build_live_client", _raise_hmac)
        with pytest.raises(HMACError, match="simulated key-permission failure"):
            cli_mod._refresh_live(db=None, source="policy-sentry")
