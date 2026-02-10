#!/usr/bin/env python3
"""
EDAMAME Score Calculator

Computes the EDAMAME Security Score for a given platform and set of check results.
Pulls threat models from https://github.com/edamametechnologies/threatmodels

The scoring algorithm mirrors the production Rust implementation in edamame_foundation.

Usage:
    # Score with all threats active (worst case)
    python score_calculator.py --platform macOS

    # Score with specific threats inactive (remediated)
    python score_calculator.py --platform macOS --inactive "local firewall disabled" "encrypted disk disabled"

    # Score with all threats inactive (best case)
    python score_calculator.py --platform macOS --all-inactive

    # Score from a JSON checks file
    python score_calculator.py --platform macOS --checks-file checks.json

    # Use a specific branch
    python score_calculator.py --platform macOS --branch main

    # Use a local threat model file
    python score_calculator.py --platform macOS --local-file threatmodel-macOS.json

    # JSON output
    python score_calculator.py --platform macOS --inactive "SIP disabled" --json
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


THREAT_MODEL_URL = (
    "https://raw.githubusercontent.com/edamametechnologies/threatmodels/{branch}/threatmodel-{platform}.json"
)

VALID_PLATFORMS = ["macOS", "Windows", "Linux", "iOS", "Android"]

DIMENSIONS = [
    "network",
    "system services",
    "system integrity",
    "credentials",
    "applications",
]


@dataclass
class MetricResult:
    """A single threat metric with its evaluated status."""

    name: str
    dimension: str
    severity: int
    tags: list[str]
    active: bool  # True = threat is present (bad), False = threat is inactive (good)


@dataclass
class DimensionScore:
    """Score for a single security dimension."""

    name: str
    current: int  # Sum of severity for inactive threats
    maximum: int  # Sum of all severities
    score: int  # Percentage 0-100, or -1 if no metrics

    @property
    def has_metrics(self) -> bool:
        return self.maximum > 0


@dataclass
class ComplianceResult:
    """Compliance percentage for a tag prefix."""

    tag: str
    compliant: int
    total: int
    percentage: float


@dataclass
class ScoreResult:
    """Complete score computation result."""

    platform: str
    dimensions: dict[str, DimensionScore]
    overall: int  # 0-100
    stars: float  # 0.0-5.0
    compliance: dict[str, ComplianceResult]
    metrics: list[MetricResult]
    total_metrics: int
    active_threats: int
    inactive_threats: int


def fetch_threat_model(platform: str, branch: str = "main") -> dict:
    """Fetch a threat model JSON from the GitHub repository.

    Args:
        platform: One of macOS, Windows, Linux, iOS, Android.
        branch: Git branch to fetch from (default: main).

    Returns:
        Parsed threat model dictionary.

    Raises:
        ValueError: If the platform is invalid.
        ConnectionError: If the fetch fails.
    """
    if platform not in VALID_PLATFORMS:
        raise ValueError(
            f"Invalid platform '{platform}'. Must be one of: {', '.join(VALID_PLATFORMS)}"
        )

    url = THREAT_MODEL_URL.format(branch=branch, platform=platform)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "edamame-score-calculator/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise ConnectionError(
            f"Failed to fetch threat model for {platform} from branch '{branch}': HTTP {e.code}"
        ) from e
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to connect to GitHub: {e.reason}") from e


def load_threat_model(path: str) -> dict:
    """Load a threat model JSON from a local file.

    Args:
        path: Path to the JSON file.

    Returns:
        Parsed threat model dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_score(
    threat_model: dict,
    inactive_threats: Optional[set[str]] = None,
    all_inactive: bool = False,
) -> ScoreResult:
    """Compute the EDAMAME Security Score from a threat model and check results.

    This implements the same algorithm as edamame_foundation's Score::compute_score()
    and Score::compute_compliance().

    Scoring algorithm:
        - Each metric belongs to one of 5 dimensions and has a severity weight (1-5).
        - For each dimension: score = 100 * (sum of severity where Inactive) / (sum of all severity)
        - If a dimension has no metrics: score = -1 (ignored by UI)
        - Overall: score = 100 * (total Inactive severity) / (total severity)
        - Stars: stars = overall * 5.0 / 100.0 (scale of 0 to 5)
        - Compliance per tag prefix: 100 * (count Inactive matching tag) / (count all matching tag)

    A threat is "Inactive" (good) if it has been remediated or does not apply.
    A threat is "Active" (bad) if the vulnerability is present on the device.

    Args:
        threat_model: Parsed threat model dictionary (from fetch or load).
        inactive_threats: Set of threat names that are inactive (remediated/not applicable).
                         If None, all threats are considered active (worst case).
        all_inactive: If True, treat all threats as inactive (best case). Overrides inactive_threats.

    Returns:
        ScoreResult with all computed scores.
    """
    if inactive_threats is None:
        inactive_threats = set()

    raw_metrics = threat_model.get("metrics", [])
    platform = threat_model.get("name", "unknown")

    # Build metric results
    metrics: list[MetricResult] = []
    for m in raw_metrics:
        name = m["name"]
        is_inactive = all_inactive or name in inactive_threats
        metrics.append(
            MetricResult(
                name=name,
                dimension=m["dimension"],
                severity=m["severity"],
                tags=m.get("tags", []),
                active=not is_inactive,
            )
        )

    # --- Dimension scores (mirrors Score::compute_score in Rust) ---
    dim_accum: dict[str, tuple[int, int]] = {d: (0, 0) for d in DIMENSIONS}

    for m in metrics:
        current, maximum = dim_accum[m.dimension]
        maximum += m.severity
        if not m.active:  # Inactive = good
            current += m.severity
        dim_accum[m.dimension] = (current, maximum)

    dimensions: dict[str, DimensionScore] = {}
    overall_current = 0
    overall_max = 0

    for dim_name in DIMENSIONS:
        current, maximum = dim_accum[dim_name]
        overall_current += current
        overall_max += maximum
        if maximum > 0:
            score = 100 * current // maximum
        else:
            score = -1  # No metrics for this dimension
        dimensions[dim_name] = DimensionScore(
            name=dim_name, current=current, maximum=maximum, score=score
        )

    overall = (100 * overall_current // overall_max) if overall_max > 0 else 0
    stars = overall * 5.0 / 100.0

    # --- Compliance (mirrors Score::compute_compliance in Rust) ---
    # Collect tag prefixes
    tag_prefixes: set[str] = set()
    for m in metrics:
        for tag in m.tags:
            if "," in tag:
                prefix = tag[: tag.index(",")]
            else:
                prefix = tag
            tag_prefixes.add(prefix)

    compliance: dict[str, ComplianceResult] = {}
    for tag in sorted(tag_prefixes):
        total = 0
        compliant = 0
        for m in metrics:
            for metric_tag in m.tags:
                if metric_tag.startswith(tag):
                    total += 1
                    if not m.active:  # Inactive = compliant
                        compliant += 1
        if total > 0:
            percentage = (100.0 * compliant) / total
            compliance[tag] = ComplianceResult(
                tag=tag, compliant=compliant, total=total, percentage=percentage
            )

    active_count = sum(1 for m in metrics if m.active)
    inactive_count = sum(1 for m in metrics if not m.active)

    return ScoreResult(
        platform=platform,
        dimensions=dimensions,
        overall=overall,
        stars=stars,
        compliance=compliance,
        metrics=metrics,
        total_metrics=len(metrics),
        active_threats=active_count,
        inactive_threats=inactive_count,
    )


def format_text_report(result: ScoreResult) -> str:
    """Format a ScoreResult as a human-readable text report."""
    lines: list[str] = []

    lines.append(f"EDAMAME Security Score - {result.platform}")
    lines.append("=" * 60)
    lines.append("")

    # Stars and overall
    filled = int(result.stars)
    half = 1 if (result.stars - filled) >= 0.5 else 0
    empty = 5 - filled - half
    star_display = "*" * filled + ("+" if half else "") + "." * empty
    lines.append(f"  Stars:   {result.stars:.1f} / 5.0  [{star_display}]")
    lines.append(f"  Overall: {result.overall}%")
    lines.append("")

    # Dimension scores
    lines.append("Dimension Scores")
    lines.append("-" * 40)
    for dim_name in DIMENSIONS:
        dim = result.dimensions[dim_name]
        if dim.score == -1:
            score_str = "N/A (no metrics)"
        else:
            score_str = f"{dim.score}%"
        label = dim.name.title()
        lines.append(f"  {label:<20s} {score_str:>6s}  ({dim.current}/{dim.maximum})")
    lines.append("")

    # Threat summary
    lines.append(f"Threats: {result.total_metrics} total, "
                 f"{result.active_threats} active, {result.inactive_threats} inactive")
    lines.append("-" * 40)
    for m in sorted(result.metrics, key=lambda x: (-x.severity, x.name)):
        status = "ACTIVE" if m.active else "OK"
        lines.append(f"  [{status:<6s}] (sev {m.severity}) {m.name}")
    lines.append("")

    # Compliance
    if result.compliance:
        lines.append("Compliance")
        lines.append("-" * 40)
        for tag in sorted(result.compliance):
            c = result.compliance[tag]
            lines.append(f"  {tag:<30s} {c.percentage:5.1f}%  ({c.compliant}/{c.total})")
        lines.append("")

    return "\n".join(lines)


def format_json_report(result: ScoreResult) -> str:
    """Format a ScoreResult as a JSON string."""
    data = {
        "platform": result.platform,
        "stars": round(result.stars, 2),
        "overall_percent": result.overall,
        "total_metrics": result.total_metrics,
        "active_threats": result.active_threats,
        "inactive_threats": result.inactive_threats,
        "dimensions": {
            name: {
                "score_percent": dim.score,
                "current_severity": dim.current,
                "max_severity": dim.maximum,
            }
            for name, dim in result.dimensions.items()
        },
        "compliance": {
            tag: {
                "percentage": round(c.percentage, 2),
                "compliant": c.compliant,
                "total": c.total,
            }
            for tag, c in result.compliance.items()
        },
        "metrics": [
            {
                "name": m.name,
                "dimension": m.dimension,
                "severity": m.severity,
                "active": m.active,
                "tags": m.tags,
            }
            for m in sorted(result.metrics, key=lambda x: (-x.severity, x.name))
        ],
    }
    return json.dumps(data, indent=2)


def load_checks_file(path: str) -> set[str]:
    """Load a checks file (JSON) containing a list of inactive threat names.

    Expected format:
        { "inactive": ["threat name 1", "threat name 2", ...] }

    Or a simple list:
        ["threat name 1", "threat name 2", ...]
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return set(data)
    if isinstance(data, dict) and "inactive" in data:
        return set(data["inactive"])
    raise ValueError(
        f"Invalid checks file format. Expected a JSON list or object with 'inactive' key."
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="EDAMAME Security Score Calculator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Worst case score (all threats active)
  %(prog)s --platform macOS

  # Specify which threats have been remediated
  %(prog)s --platform macOS --inactive "local firewall disabled" "SIP disabled"

  # Best case score
  %(prog)s --platform macOS --all-inactive

  # Load checks from file
  %(prog)s --platform Linux --checks-file my_checks.json

  # Use local threat model file
  %(prog)s --platform macOS --local-file threatmodel-macOS.json

  # JSON output
  %(prog)s --platform macOS --json
""",
    )
    parser.add_argument(
        "--platform",
        required=True,
        choices=VALID_PLATFORMS,
        help="Target platform (macOS, Windows, Linux, iOS, Android)",
    )
    parser.add_argument(
        "--inactive",
        nargs="*",
        default=[],
        metavar="THREAT",
        help="Names of threats that are inactive (remediated)",
    )
    parser.add_argument(
        "--all-inactive",
        action="store_true",
        help="Treat all threats as inactive (best case score)",
    )
    parser.add_argument(
        "--checks-file",
        metavar="FILE",
        help="JSON file with list of inactive threat names",
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Git branch to fetch threat model from (default: main)",
    )
    parser.add_argument(
        "--local-file",
        metavar="FILE",
        help="Use a local threat model JSON file instead of fetching from GitHub",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--list-threats",
        action="store_true",
        help="List all threat names in the model and exit",
    )

    args = parser.parse_args(argv)

    # Load threat model
    try:
        if args.local_file:
            threat_model = load_threat_model(args.local_file)
        else:
            threat_model = fetch_threat_model(args.platform, args.branch)
    except (ConnectionError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading threat model: {e}", file=sys.stderr)
        return 1

    # List threats mode
    if args.list_threats:
        for m in threat_model.get("metrics", []):
            dim = m["dimension"]
            sev = m["severity"]
            name = m["name"]
            tags = ", ".join(m.get("tags", []))
            tag_str = f"  [{tags}]" if tags else ""
            print(f"  (sev {sev}, {dim}) {name}{tag_str}")
        return 0

    # Build inactive set
    inactive: set[str] = set(args.inactive)
    if args.checks_file:
        try:
            inactive |= load_checks_file(args.checks_file)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            print(f"Error loading checks file: {e}", file=sys.stderr)
            return 1

    # Validate threat names
    known_names = {m["name"] for m in threat_model.get("metrics", [])}
    unknown = inactive - known_names
    if unknown and not args.all_inactive:
        print(
            f"Warning: unknown threat names (ignored): {', '.join(sorted(unknown))}",
            file=sys.stderr,
        )

    # Compute
    result = compute_score(threat_model, inactive, args.all_inactive)

    # Output
    if args.json_output:
        print(format_json_report(result))
    else:
        print(format_text_report(result))

    return 0


if __name__ == "__main__":
    sys.exit(main())
