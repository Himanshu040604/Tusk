"""Tests for the database refresh mechanisms."""

import json
from pathlib import Path

import pytest

from src.sentinel.database import Database, Service

from src.sentinel.refresh.policy_sentry_loader import (
    PolicySentryLoader,
    RefreshStats,
    ChangelogEntry,
)
from src.sentinel.refresh.aws_docs_scraper import (
    AwsDocsScraper,
    ServiceAuthorizationParser,
)


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------

SAMPLE_SERVICE_JSON = {
    "prefix": "s3",
    "service_name": "Amazon S3",
    "privileges": [
        {"privilege": "GetObject", "access_level": "Read", "description": "Read an object"},
        {"privilege": "PutObject", "access_level": "Write", "description": "Write an object"},
        {"privilege": "ListBucket", "access_level": "List", "description": "List bucket"},
    ],
    "resources": [
        {"resource": "bucket", "arn": "arn:aws:s3:::${BucketName}"},
        {"resource": "object", "arn": "arn:aws:s3:::${BucketName}/${ObjectKey}"},
    ],
    "conditions": [
        {"condition": "s3:authType", "type": "String"},
        {"condition": "aws:SourceIp", "type": "IPAddress"},
    ],
}

SAMPLE_HTML = """
<html>
<body>
<h1>Actions defined by Amazon S3</h1>
<table>
<thead><tr><th>Actions</th><th>Description</th><th>Access level</th></tr></thead>
<tbody>
<tr><td>GetObject</td><td>Read an object</td><td>Read</td></tr>
<tr><td>PutObject</td><td>Write an object</td><td>Write</td></tr>
</tbody>
</table>
<table>
<thead><tr><th>Resource types</th><th>ARN</th></tr></thead>
<tbody>
<tr><td>bucket</td><td>arn:aws:s3:::*</td></tr>
</tbody>
</table>
<table>
<thead><tr><th>Condition keys</th><th>Description</th><th>Type</th></tr></thead>
<tbody>
<tr><td>s3:authType</td><td>Auth type</td><td>String</td></tr>
</tbody>
</table>
</body>
</html>
"""


@pytest.fixture
def fresh_db(tmp_path: Path) -> Database:
    """Create a fresh database with schema."""
    db = Database(tmp_path / "iam_actions.db")
    db.create_schema()
    return db


@pytest.fixture
def sample_policy_sentry_json(tmp_path: Path) -> Path:
    """Create a sample policy_sentry JSON file."""
    f = tmp_path / "s3.json"
    f.write_text(json.dumps(SAMPLE_SERVICE_JSON), encoding="utf-8")
    return f


@pytest.fixture
def sample_policy_sentry_dir(tmp_path: Path) -> Path:
    """Create a directory of policy_sentry JSON files."""
    d = tmp_path / "services"
    d.mkdir()
    (d / "s3.json").write_text(json.dumps(SAMPLE_SERVICE_JSON), encoding="utf-8")
    ec2_data = {
        "prefix": "ec2",
        "service_name": "Amazon EC2",
        "privileges": [
            {"privilege": "DescribeInstances", "access_level": "List"},
        ],
        "resources": [],
        "conditions": [],
    }
    (d / "ec2.json").write_text(json.dumps(ec2_data), encoding="utf-8")
    return d


@pytest.fixture
def sample_html_file(tmp_path: Path) -> Path:
    """Create a saved HTML file."""
    f = tmp_path / "list_amazons3.html"
    f.write_text(SAMPLE_HTML, encoding="utf-8")
    return f


@pytest.fixture
def sample_html_dir(tmp_path: Path) -> Path:
    """Create a directory of saved HTML files."""
    d = tmp_path / "html_docs"
    d.mkdir()
    (d / "list_amazons3.html").write_text(SAMPLE_HTML, encoding="utf-8")
    return d


# -----------------------------------------------------------------------
# TestPolicySentryLoader
# -----------------------------------------------------------------------


class TestPolicySentryLoader:
    """Test PolicySentryLoader."""

    def test_load_from_file(self, fresh_db: Database, sample_policy_sentry_json: Path):
        loader = PolicySentryLoader(fresh_db)
        stats, changelog = loader.load_from_file(sample_policy_sentry_json)

        assert stats.services_added == 1
        assert stats.actions_added == 3
        assert stats.resource_types_added == 2
        assert stats.condition_keys_added == 2
        assert len(stats.errors) == 0

    def test_load_from_directory(self, fresh_db: Database, sample_policy_sentry_dir: Path):
        loader = PolicySentryLoader(fresh_db)
        stats, changelog = loader.load_from_directory(sample_policy_sentry_dir)

        assert stats.services_added == 2  # s3 + ec2
        assert stats.actions_added == 4  # 3 s3 + 1 ec2

    def test_access_level_flag_mapping(self, fresh_db: Database, sample_policy_sentry_json: Path):
        loader = PolicySentryLoader(fresh_db)
        loader.load_from_file(sample_policy_sentry_json)

        # Verify is_read flag on GetObject
        action = fresh_db.get_action("s3", "GetObject")
        assert action is not None
        assert action.is_read is True
        assert action.is_write is False

        # Verify is_write flag on PutObject
        action = fresh_db.get_action("s3", "PutObject")
        assert action is not None
        assert action.is_write is True
        assert action.is_read is False

        # Verify is_list flag on ListBucket
        action = fresh_db.get_action("s3", "ListBucket")
        assert action is not None
        assert action.is_list is True

    def test_resource_type_insertion(self, fresh_db: Database, sample_policy_sentry_json: Path):
        loader = PolicySentryLoader(fresh_db)
        loader.load_from_file(sample_policy_sentry_json)

        with fresh_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM resource_types WHERE service_prefix = 's3'")
            count = cursor.fetchone()["c"]
        assert count == 2

    def test_condition_key_insertion(self, fresh_db: Database, sample_policy_sentry_json: Path):
        loader = PolicySentryLoader(fresh_db)
        loader.load_from_file(sample_policy_sentry_json)

        with fresh_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM condition_keys WHERE service_prefix = 's3'")
            count = cursor.fetchone()["c"]
        assert count == 2

    def test_malformed_json_in_directory(self, fresh_db: Database, tmp_path: Path):
        d = tmp_path / "bad_dir"
        d.mkdir()
        (d / "bad.json").write_text("not valid json", encoding="utf-8")

        loader = PolicySentryLoader(fresh_db)
        stats, changelog = loader.load_from_directory(d)
        assert len(stats.errors) == 1
        assert "bad.json" in stats.errors[0]

    def test_missing_prefix(self, fresh_db: Database, tmp_path: Path):
        f = tmp_path / "no_prefix.json"
        f.write_text(json.dumps({"service_name": "Test"}), encoding="utf-8")

        loader = PolicySentryLoader(fresh_db)
        stats, changelog = loader.load_from_file(f)
        # No prefix means it can't be processed as a single-service file
        # but the multi-service path may still work -- check no crash
        assert isinstance(stats, RefreshStats)

    def test_multi_service_file(self, fresh_db: Database, tmp_path: Path):
        multi = {
            "s3": SAMPLE_SERVICE_JSON,
            "ec2": {
                "prefix": "ec2",
                "service_name": "Amazon EC2",
                "privileges": [
                    {"privilege": "RunInstances", "access_level": "Write"},
                ],
                "resources": [],
                "conditions": [],
            },
        }
        f = tmp_path / "multi.json"
        f.write_text(json.dumps(multi), encoding="utf-8")

        loader = PolicySentryLoader(fresh_db)
        stats, changelog = loader.load_from_file(f)
        assert stats.services_added == 2
        assert stats.actions_added == 4  # 3 s3 + 1 ec2

    def test_idempotent_refresh(self, fresh_db: Database, sample_policy_sentry_json: Path):
        loader = PolicySentryLoader(fresh_db)
        stats1, _ = loader.load_from_file(sample_policy_sentry_json)
        stats2, _ = loader.load_from_file(sample_policy_sentry_json)

        # Second run should succeed without errors (INSERT OR REPLACE)
        assert len(stats2.errors) == 0
        assert stats1.actions_added == stats2.actions_added


# -----------------------------------------------------------------------
# TestDryRun
# -----------------------------------------------------------------------


class TestDryRun:
    """Test dry-run validation."""

    def test_valid_data_no_errors(self, fresh_db: Database, sample_policy_sentry_json: Path):
        loader = PolicySentryLoader(fresh_db)
        errors = loader.validate_data(sample_policy_sentry_json)
        assert len(errors) == 0

    def test_valid_directory_no_errors(self, fresh_db: Database, sample_policy_sentry_dir: Path):
        loader = PolicySentryLoader(fresh_db)
        errors = loader.validate_data(sample_policy_sentry_dir)
        assert len(errors) == 0

    def test_invalid_json_reported(self, fresh_db: Database, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json}", encoding="utf-8")

        loader = PolicySentryLoader(fresh_db)
        errors = loader.validate_data(bad)
        assert len(errors) >= 1

    def test_empty_directory_reported(self, fresh_db: Database, tmp_path: Path):
        d = tmp_path / "empty"
        d.mkdir()

        loader = PolicySentryLoader(fresh_db)
        errors = loader.validate_data(d)
        assert any("No JSON files" in e for e in errors)

    def test_db_stays_empty(self, fresh_db: Database, sample_policy_sentry_json: Path):
        loader = PolicySentryLoader(fresh_db)
        loader.validate_data(sample_policy_sentry_json)

        # DB should have no services after dry-run
        services = fresh_db.get_services()
        assert len(services) == 0

    def test_unknown_access_level(self, fresh_db: Database, tmp_path: Path):
        data = {
            "prefix": "test",
            "service_name": "Test",
            "privileges": [
                {"privilege": "DoSomething", "access_level": "SuperAdmin"},
            ],
            "resources": [],
            "conditions": [],
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data), encoding="utf-8")

        loader = PolicySentryLoader(fresh_db)
        errors = loader.validate_data(f)
        assert any("SuperAdmin" in e for e in errors)


# -----------------------------------------------------------------------
# TestChangelogEntry
# -----------------------------------------------------------------------


class TestChangelogEntry:
    """Test ChangelogEntry dataclass."""

    def test_fields(self):
        entry = ChangelogEntry(
            change_type="ADD",
            entity_type="action",
            entity_name="s3:GetObject",
            detail="Access level: Read",
        )
        assert entry.change_type == "ADD"
        assert entry.entity_type == "action"
        assert entry.entity_name == "s3:GetObject"
        assert entry.detail == "Access level: Read"


# -----------------------------------------------------------------------
# TestServiceAuthorizationParser
# -----------------------------------------------------------------------


class TestServiceAuthorizationParser:
    """Test the HTML table parser."""

    def test_parse_actions(self):
        parser = ServiceAuthorizationParser()
        parser.feed(SAMPLE_HTML)
        assert len(parser.actions) == 2
        assert parser.actions[0]["privilege"] == "GetObject"
        assert parser.actions[1]["access_level"] == "Write"

    def test_parse_resource_types(self):
        parser = ServiceAuthorizationParser()
        parser.feed(SAMPLE_HTML)
        assert len(parser.resource_types) == 1
        assert parser.resource_types[0]["resource"] == "bucket"

    def test_parse_condition_keys(self):
        parser = ServiceAuthorizationParser()
        parser.feed(SAMPLE_HTML)
        assert len(parser.condition_keys) == 1
        assert parser.condition_keys[0]["condition"] == "s3:authType"

    def test_empty_html(self):
        parser = ServiceAuthorizationParser()
        parser.feed("<html><body></body></html>")
        assert len(parser.actions) == 0
        assert len(parser.resource_types) == 0
        assert len(parser.condition_keys) == 0


# -----------------------------------------------------------------------
# TestAwsDocsScraper
# -----------------------------------------------------------------------


class TestAwsDocsScraper:
    """Test AwsDocsScraper."""

    def test_load_from_file(self, fresh_db: Database, sample_html_file: Path):
        scraper = AwsDocsScraper(fresh_db)
        stats, changelog = scraper.load_from_file(sample_html_file)

        assert stats.services_added == 1
        assert stats.actions_added == 2
        assert stats.resource_types_added == 1
        assert stats.condition_keys_added == 1

    def test_load_from_directory(self, fresh_db: Database, sample_html_dir: Path):
        scraper = AwsDocsScraper(fresh_db)
        stats, changelog = scraper.load_from_directory(sample_html_dir)

        assert stats.services_added >= 1
        assert stats.actions_added >= 2

    def test_infer_service_prefix_list_amazon(self, fresh_db: Database):
        scraper = AwsDocsScraper(fresh_db)
        prefix = scraper._infer_service_prefix("list_amazons3.html", "")
        assert prefix == "s3"

    def test_infer_service_prefix_list_aws(self, fresh_db: Database):
        scraper = AwsDocsScraper(fresh_db)
        prefix = scraper._infer_service_prefix("list_awslambda.html", "")
        assert prefix == "lambda"

    def test_infer_service_prefix_simple(self, fresh_db: Database):
        scraper = AwsDocsScraper(fresh_db)
        prefix = scraper._infer_service_prefix("ec2.html", "")
        assert prefix == "ec2"

    def test_infer_service_prefix_from_content(self, fresh_db: Database):
        scraper = AwsDocsScraper(fresh_db)
        content = "<p>service prefix: <code>dynamodb</code></p>"
        # Filename with uppercase/spaces won't match the simple stem pattern,
        # forcing the content-based fallback to fire.
        prefix = scraper._infer_service_prefix("Unknown Service.html", content)
        assert prefix == "dynamodb"

    def test_validate_data_file(self, fresh_db: Database, sample_html_file: Path):
        scraper = AwsDocsScraper(fresh_db)
        errors = scraper.validate_data(sample_html_file)
        assert len(errors) == 0

    def test_validate_data_empty_dir(self, fresh_db: Database, tmp_path: Path):
        d = tmp_path / "empty_html"
        d.mkdir()
        scraper = AwsDocsScraper(fresh_db)
        errors = scraper.validate_data(d)
        assert any("No HTML files" in e for e in errors)

    def test_actions_stored_in_db(self, fresh_db: Database, sample_html_file: Path):
        scraper = AwsDocsScraper(fresh_db)
        scraper.load_from_file(sample_html_file)

        action = fresh_db.get_action("s3", "GetObject")
        assert action is not None
        assert action.access_level == "Read"
