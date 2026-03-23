"""AWS IAM policy example fetcher, normalizer, and benchmarking module.

Fetches real-world IAM policy examples from AWS GitHub repositories via
the ``gh`` CLI, normalizes them for the Sentinel pipeline, runs benchmarks,
and reports DB coverage gaps.
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from src.sentinel.database import Database
    from src.sentinel.inventory import ResourceInventory


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RepoConfig:
    """Configuration for a single AWS example repository.

    Attributes:
        owner: GitHub organization or user.
        repo: Repository name.
        description: Human-readable label.
        exclude_files: Filenames to skip (e.g. package.json).
    """

    owner: str
    repo: str
    description: str
    exclude_files: Set[str] = field(
        default_factory=lambda: {
            "package.json",
            "package-lock.json",
            "tsconfig.json",
            ".eslintrc.json",
        },
    )

    @property
    def full_name(self) -> str:
        """Return owner/repo string."""
        return f"{self.owner}/{self.repo}"


DEFAULT_REPOS: List[RepoConfig] = [
    RepoConfig(
        owner="aws-samples",
        repo="service-control-policy-examples",
        description="AWS SCP examples",
    ),
    RepoConfig(
        owner="aws-samples",
        repo="data-perimeter-policy-examples",
        description="AWS data perimeter policies",
    ),
    RepoConfig(
        owner="aws-samples",
        repo="how-and-when-to-use-aws-iam-policy-blog-samples",
        description="AWS IAM policy type examples",
    ),
]


@dataclass
class NormalizedPolicy:
    """A validated IAM policy ready for pipeline ingestion.

    Attributes:
        source_repo: Origin repository full name.
        relative_path: Path within the repo.
        category: Inferred category from directory structure.
        policy_type: One of scp, identity, resource, boundary, vpc_endpoint.
        local_path: Absolute path to the saved JSON file.
        statement_count: Number of Statement entries.
        uses_not_action: Whether any statement uses NotAction.
        uses_conditions: Whether any statement uses Condition.
    """

    source_repo: str
    relative_path: str
    category: str
    policy_type: str
    local_path: Path
    statement_count: int = 0
    uses_not_action: bool = False
    uses_conditions: bool = False


@dataclass
class BenchmarkEntry:
    """Result of running a single policy through the pipeline.

    Attributes:
        policy_path: Path to the policy file.
        source_repo: Origin repository.
        category: Policy category.
        success: Whether the pipeline completed without error.
        error: Error message if pipeline failed.
        tier1_count: Number of Tier 1 (valid) actions.
        tier2_count: Number of Tier 2 (unknown) actions.
        tier3_count: Number of Tier 3 (invalid) actions.
        risk_count: Number of risk findings.
        rewrite_changes: Number of rewrite changes applied.
        verdict: Self-check verdict string.
        original_action_count: Actions in original policy.
        rewritten_action_count: Actions in rewritten policy.
        wildcards_resolved: Wildcard patterns expanded to specifics.
        wildcards_surviving: Wildcard patterns remaining after rewrite.
        completeness_score: Self-check completeness score (0.0-1.0).
        elapsed_ms: Pipeline execution time in milliseconds.
    """

    policy_path: str
    source_repo: str
    category: str
    success: bool
    error: Optional[str] = None
    tier1_count: int = 0
    tier2_count: int = 0
    tier3_count: int = 0
    risk_count: int = 0
    rewrite_changes: int = 0
    verdict: Optional[str] = None
    original_action_count: int = 0
    rewritten_action_count: int = 0
    wildcards_resolved: int = 0
    wildcards_surviving: int = 0
    completeness_score: float = 0.0
    elapsed_ms: float = 0.0


# ---------------------------------------------------------------------------
# Module-level helpers (extracted to keep classes under 100 lines)
# ---------------------------------------------------------------------------

def verify_gh_cli() -> None:
    """Check that the ``gh`` CLI is installed and authenticated.

    Raises:
        RuntimeError: If ``gh`` is not available or not authenticated.
    """
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "gh CLI is not authenticated. Run: gh auth login"
            )
    except FileNotFoundError:
        raise RuntimeError(
            "gh CLI not found. Install from: https://cli.github.com/"
        )


def run_gh_api(
    endpoint: str,
    params: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Execute a ``gh api`` call and return parsed JSON.

    Args:
        endpoint: GitHub API endpoint path.
        params: Optional query string (appended with ?).

    Returns:
        Parsed JSON dict or None on failure.
    """
    url = f"{endpoint}?{params}" if params else endpoint
    try:
        result = subprocess.run(
            ["gh", "api", url],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def is_iam_policy(data: Any) -> bool:
    """Check if JSON data looks like an IAM policy document."""
    if not isinstance(data, dict):
        return False
    return "Statement" in data and "Version" in data


def infer_category(relative_path: str) -> str:
    """Infer policy category from directory structure."""
    parts = Path(relative_path).parts
    if len(parts) >= 2:
        return parts[1].lower().replace(" ", "-")
    return "uncategorized"


def infer_policy_type(relative_path: str, data: Dict[str, Any]) -> str:
    """Infer the IAM policy type from path and content."""
    path_lower = relative_path.lower()
    if "scp" in path_lower or "service_control" in path_lower:
        return "scp"
    if "rcp" in path_lower or "resource_control" in path_lower:
        return "rcp"
    if "vpc_endpoint" in path_lower or "vpce" in path_lower:
        return "vpc_endpoint"
    if "boundary" in path_lower or "permissions-boundary" in path_lower:
        return "boundary"
    if "resource-policy" in path_lower:
        return "resource"

    statements = data.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    all_deny = all(
        s.get("Effect") == "Deny" for s in statements if isinstance(s, dict)
    )
    if all_deny and len(statements) > 0:
        return "scp"
    return "identity"


def write_manifest(
    output_dir: Path,
    policies: List[NormalizedPolicy],
) -> Path:
    """Write manifest.json summarizing all normalized policies."""
    manifest: Dict[str, Any] = {
        "total_policies": len(policies),
        "by_type": {},
        "by_repo": {},
        "policies": [],
    }
    for p in policies:
        manifest["by_type"][p.policy_type] = (
            manifest["by_type"].get(p.policy_type, 0) + 1
        )
        manifest["by_repo"][p.source_repo] = (
            manifest["by_repo"].get(p.source_repo, 0) + 1
        )
        manifest["policies"].append({
            "source_repo": p.source_repo,
            "relative_path": p.relative_path,
            "category": p.category,
            "policy_type": p.policy_type,
            "statement_count": p.statement_count,
            "uses_not_action": p.uses_not_action,
            "uses_conditions": p.uses_conditions,
        })
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest_path


def format_pct(part: int, total: int) -> str:
    """Compute percentage string."""
    if total == 0:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


def count_wildcards(actions: List[str]) -> int:
    """Count wildcard patterns in an action list.

    Counts full wildcards (*, *:*), service wildcards (s3:*),
    and prefix/suffix wildcards (s3:Get*, s3:*Object).
    """
    count = 0
    for action in actions:
        if action in ("*", "*:*"):
            count += 1
        elif "*" in action:
            count += 1
    return count


def collect_policy_actions(policy: Any) -> List[str]:
    """Extract all actions from a Policy object."""
    actions: List[str] = []
    for stmt in policy.statements:
        actions.extend(stmt.actions)
        if stmt.not_actions:
            actions.extend(stmt.not_actions)
    return actions


# ---------------------------------------------------------------------------
# ExampleFetcher
# ---------------------------------------------------------------------------

class ExampleFetcher:
    """Fetches JSON policy files from AWS GitHub repos via ``gh api``.

    Uses the Git Trees API to list files and the Contents API to download
    each JSON file. Saves raw files to *output_dir/repo-name/*.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        verify_gh_cli()

    def fetch_all(
        self,
        repos: Optional[List[RepoConfig]] = None,
    ) -> List[Path]:
        """Fetch JSON policy files from all configured repos."""
        repos = repos or DEFAULT_REPOS
        downloaded: List[Path] = []
        for repo_config in repos:
            downloaded.extend(self._fetch_repo(repo_config))
        return downloaded

    def _fetch_repo(self, config: RepoConfig) -> List[Path]:
        """Fetch all JSON files from a single repo."""
        tree = run_gh_api(
            f"repos/{config.owner}/{config.repo}/git/trees/main",
            params="recursive=1",
        )
        if tree is None:
            return []

        json_paths = [
            e["path"]
            for e in tree.get("tree", [])
            if (
                e.get("type") == "blob"
                and e["path"].endswith(".json")
                and Path(e["path"]).name not in config.exclude_files
            )
        ]

        results: List[Path] = []
        repo_dir = self.output_dir / config.repo
        repo_dir.mkdir(parents=True, exist_ok=True)

        for file_path in json_paths:
            content = self._download_file(config, file_path)
            if content is not None:
                dest = repo_dir / file_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(
                    json.dumps(content, indent=2) + "\n", encoding="utf-8"
                )
                results.append(dest)
        return results

    @staticmethod
    def _download_file(
        config: RepoConfig,
        path: str,
    ) -> Optional[Dict[str, Any]]:
        """Download and decode a single JSON file from GitHub."""
        resp = run_gh_api(
            f"repos/{config.owner}/{config.repo}/contents/{path}",
        )
        if resp is None:
            return None
        content_b64 = resp.get("content", "")
        try:
            raw = base64.b64decode(content_b64).decode("utf-8")
            return json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            return None


# ---------------------------------------------------------------------------
# PolicyNormalizer
# ---------------------------------------------------------------------------

class PolicyNormalizer:
    """Validates and tags downloaded JSON files as IAM policies.

    Filters out non-policy JSON, infers category and type, writes
    normalized copies and a manifest.json.
    """

    def __init__(self, input_dir: Path, output_dir: Path) -> None:
        self.input_dir = input_dir
        self.output_dir = output_dir

    def normalize_all(self) -> List[NormalizedPolicy]:
        """Scan input_dir, validate and normalize all IAM policies."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        policies: List[NormalizedPolicy] = []
        for json_file in sorted(self.input_dir.rglob("*.json")):
            policy = self._try_normalize(json_file)
            if policy is not None:
                policies.append(policy)
        write_manifest(self.output_dir, policies)
        return policies

    def _try_normalize(self, path: Path) -> Optional[NormalizedPolicy]:
        """Attempt to normalize a single JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        if not is_iam_policy(data):
            return None

        relative = path.relative_to(self.input_dir)
        repo_name = relative.parts[0] if relative.parts else "unknown"

        statements = data.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        dest = self.output_dir / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(data, indent=2) + "\n", encoding="utf-8"
        )

        return NormalizedPolicy(
            source_repo=repo_name,
            relative_path=str(relative),
            category=infer_category(str(relative)),
            policy_type=infer_policy_type(str(relative), data),
            local_path=dest,
            statement_count=len(statements),
            uses_not_action=any(
                "NotAction" in s for s in statements if isinstance(s, dict)
            ),
            uses_conditions=any(
                "Condition" in s for s in statements if isinstance(s, dict)
            ),
        )


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------

class BenchmarkRunner:
    """Feeds normalized policies through the Sentinel pipeline."""

    def __init__(
        self,
        database: Optional[Database] = None,
        inventory: Optional[ResourceInventory] = None,
    ) -> None:
        self.database = database
        self.inventory = inventory

    def run_benchmark(
        self,
        policies: List[NormalizedPolicy],
    ) -> List[BenchmarkEntry]:
        """Run all policies through the pipeline."""
        return [self._run_single(p) for p in policies]

    def _run_single(self, policy: NormalizedPolicy) -> BenchmarkEntry:
        """Run a single policy through the pipeline."""
        import time
        from src.sentinel.self_check import Pipeline, PipelineConfig
        from src.sentinel.parser import ValidationTier

        entry = BenchmarkEntry(
            policy_path=str(policy.local_path),
            source_repo=policy.source_repo,
            category=policy.category,
            success=False,
        )
        try:
            policy_json = policy.local_path.read_text(encoding="utf-8")
            pipeline = Pipeline(self.database, self.inventory)
            config = PipelineConfig(max_self_check_retries=1)

            start = time.monotonic()
            result = pipeline.run(policy_json, config)
            entry.elapsed_ms = (time.monotonic() - start) * 1000

            entry.success = True
            entry.verdict = result.final_verdict.value
            for vr in result.validation_results:
                if vr.tier == ValidationTier.TIER_1_VALID:
                    entry.tier1_count += 1
                elif vr.tier == ValidationTier.TIER_2_UNKNOWN:
                    entry.tier2_count += 1
                elif vr.tier == ValidationTier.TIER_3_INVALID:
                    entry.tier3_count += 1
            entry.risk_count = len(result.risk_findings)
            entry.rewrite_changes = len(result.rewrite_result.changes)

            orig = collect_policy_actions(result.original_policy)
            rewr = collect_policy_actions(result.rewritten_policy)
            entry.original_action_count = len(orig)
            entry.rewritten_action_count = len(rewr)
            entry.wildcards_resolved = (
                count_wildcards(orig) - count_wildcards(rewr)
            )
            entry.wildcards_surviving = count_wildcards(rewr)
            entry.completeness_score = (
                result.self_check_result.completeness_score
            )
        except Exception as exc:
            entry.error = str(exc)
        return entry


# ---------------------------------------------------------------------------
# BenchmarkReporter
# ---------------------------------------------------------------------------

class BenchmarkReporter:
    """Aggregates benchmark results into a structured report."""

    def generate_report(
        self,
        entries: List[BenchmarkEntry],
    ) -> Dict[str, Any]:
        """Generate aggregate benchmark report."""
        succeeded = [e for e in entries if e.success]
        failed = [e for e in entries if not e.success]
        t1 = sum(e.tier1_count for e in succeeded)
        t2 = sum(e.tier2_count for e in succeeded)
        t3 = sum(e.tier3_count for e in succeeded)
        total_actions = t1 + t2 + t3

        verdicts: Dict[str, int] = {}
        for e in succeeded:
            v = e.verdict or "UNKNOWN"
            verdicts[v] = verdicts.get(v, 0) + 1

        by_repo: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for e in entries:
            by_repo[e.source_repo] = by_repo.get(e.source_repo, 0) + 1
            by_cat[e.category] = by_cat.get(e.category, 0) + 1

        return {
            "summary": {
                "total_policies": len(entries),
                "succeeded": len(succeeded),
                "failed": len(failed),
            },
            "tiers": {
                "tier1_valid": t1,
                "tier2_unknown": t2,
                "tier3_invalid": t3,
                "total_actions": total_actions,
                "tier1_pct": format_pct(t1, total_actions),
                "tier2_pct": format_pct(t2, total_actions),
                "tier3_pct": format_pct(t3, total_actions),
            },
            "verdicts": verdicts,
            "by_repo": by_repo,
            "by_category": by_cat,
            "failures": [
                {"path": e.policy_path, "error": e.error} for e in failed
            ],
        }

    @staticmethod
    def format_text(report: Dict[str, Any]) -> str:
        """Format report as human-readable text."""
        s = report["summary"]
        t = report["tiers"]
        lines = [
            "=== AWS Policy Benchmark Report ===",
            "",
            f"Policies: {s['total_policies']} total, "
            f"{s['succeeded']} succeeded, {s['failed']} failed",
            "",
            "--- Action Tier Distribution ---",
            f"  Tier 1 (valid):   {t['tier1_valid']:>5}  ({t['tier1_pct']})",
            f"  Tier 2 (unknown): {t['tier2_unknown']:>5}  ({t['tier2_pct']})",
            f"  Tier 3 (invalid): {t['tier3_invalid']:>5}  ({t['tier3_pct']})",
            f"  Total actions:    {t['total_actions']:>5}",
            "",
            "--- Self-Check Verdicts ---",
        ]
        for verdict, count in report["verdicts"].items():
            lines.append(f"  {verdict}: {count}")
        if report["failures"]:
            lines.append("")
            lines.append("--- Failures ---")
            for f in report["failures"]:
                lines.append(f"  {f['path']}: {f['error']}")
        return "\n".join(lines) + "\n"
