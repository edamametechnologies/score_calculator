# EDAMAME Score Calculator

A Python utility that computes the [EDAMAME Security Score](https://github.com/edamametechnologies) from a threat model and a set of check results.

The scoring algorithm mirrors the production Rust implementation in [`edamame_foundation`](https://github.com/edamametechnologies/edamame_foundation), producing identical results.

## Overview

EDAMAME Security assesses endpoint security posture by evaluating a set of threat metrics across five security dimensions. Each metric has a severity weight (1-5) and belongs to one dimension. The score is computed as a severity-weighted ratio of inactive (remediated) threats to total threats.

This calculator fetches threat models directly from the [edamametechnologies/threatmodels](https://github.com/edamametechnologies/threatmodels) repository and computes:

- **Per-dimension scores** (0-100%) for network, system services, system integrity, credentials, and applications
- **Overall score** (0-100%) across all dimensions
- **Star rating** (0.0-5.0)
- **Compliance percentages** per tag prefix (CIS Benchmark, ISO 27001/2, SOC 2, etc.)

## Installation

No external dependencies required. Python 3.10+ with standard library only.

```bash
git clone https://github.com/edamametechnologies/score_calculator.git
cd score_calculator
```

## Usage

### Basic usage

```bash
# Worst case score (all threats active)
python score_calculator.py --platform macOS

# Specify which threats have been remediated
python score_calculator.py --platform macOS --inactive "local firewall disabled" "SIP disabled"

# Best case score (all threats inactive)
python score_calculator.py --platform macOS --all-inactive
```

### List available threats

```bash
python score_calculator.py --platform macOS --list-threats
```

### Load checks from a file

Create a JSON file with the list of inactive (remediated) threats:

```json
{
  "inactive": [
    "local firewall disabled",
    "encrypted disk disabled",
    "SIP disabled"
  ]
}
```

Or as a simple list:

```json
["local firewall disabled", "encrypted disk disabled"]
```

Then:

```bash
python score_calculator.py --platform macOS --checks-file my_checks.json
```

### Use a local threat model file

```bash
python score_calculator.py --platform macOS --local-file path/to/threatmodel-macOS.json
```

### JSON output

```bash
python score_calculator.py --platform macOS --all-inactive --json
```

### Use a specific branch

```bash
python score_calculator.py --platform macOS --branch develop
```

## Supported Platforms

- macOS
- Windows
- Linux
- iOS
- Android

## Scoring Algorithm

The algorithm is a direct port of `Score::compute_score()` and `Score::compute_compliance()` from [`edamame_foundation/src/score.rs`](https://github.com/edamametechnologies/edamame_foundation).

### Dimension Scores

Each threat metric belongs to one of five dimensions and has a severity weight (1-5). For each dimension:

```
dimension_score = 100 * (sum of severity where threat is Inactive) / (sum of all severity)
```

Integer division is used (floor), matching the Rust implementation. If a dimension has no metrics, the score is `-1` (ignored by UI).

### Overall Score

```
overall = 100 * (total Inactive severity across all dimensions) / (total severity across all dimensions)
```

### Star Rating

```
stars = overall * 5.0 / 100.0
```

Produces a value from 0.0 (worst) to 5.0 (best).

### Compliance

For each compliance tag prefix (e.g., "CIS Benchmark Level 1", "ISO 27001/2", "SOC 2"):

```
compliance = 100 * (count of Inactive metrics matching tag) / (count of all metrics matching tag)
```

Compliance is computed per tag prefix -- the part before the first comma in a tag string.

### Threat Status

- **Inactive** (good): The threat has been remediated or does not apply. Contributes to the score.
- **Active** (bad): The vulnerability is present on the device. Does not contribute to the score.

## Example Output

### Text report

```
EDAMAME Security Score - threat model macOS
============================================================

  Stars:   0.6 / 5.0  [+....]
  Overall: 11%

Dimension Scores
----------------------------------------
  Network                 25%  (2/8)
  System Services         26%  (4/15)
  System Integrity        10%  (5/46)
  Credentials              0%  (0/12)
  Applications             0%  (0/15)

Threats: 30 total, 27 active, 3 inactive
----------------------------------------
  [ACTIVE] (sev 5) MDM profiles
  [OK    ] (sev 5) SIP disabled
  ...

Compliance
----------------------------------------
  CIS Benchmark Level 1           16.7%  (3/18)
  ISO 27001/2                     33.3%  (1/3)
  Personal Posture                 0.0%  (0/7)
  SOC 2                           33.3%  (1/3)
```

### JSON report

```json
{
  "platform": "threat model macOS",
  "stars": 3.45,
  "overall_percent": 69,
  "total_metrics": 30,
  "active_threats": 10,
  "inactive_threats": 20,
  "dimensions": {
    "network": {"score_percent": 75, "current_severity": 6, "max_severity": 8}
  },
  "compliance": {
    "CIS Benchmark Level 1": {"percentage": 72.22, "compliant": 13, "total": 18}
  },
  "metrics": [
    {"name": "SIP disabled", "dimension": "system integrity", "severity": 5, "active": false, "tags": ["CIS Benchmark Level 1,Ensure System Integrity Protection is enabled"]}
  ]
}
```

## Programmatic Usage

```python
from score_calculator import fetch_threat_model, compute_score, load_threat_model

# Fetch from GitHub
model = fetch_threat_model("macOS", branch="main")

# Or load from a local file
model = load_threat_model("path/to/threatmodel-macOS.json")

# Compute with specific inactive threats
result = compute_score(model, inactive_threats={"local firewall disabled", "SIP disabled"})

print(f"Stars: {result.stars:.1f}")
print(f"Overall: {result.overall}%")
for dim_name, dim in result.dimensions.items():
    print(f"  {dim_name}: {dim.score}%")
for tag, compliance in result.compliance.items():
    print(f"  {tag}: {compliance.percentage:.1f}%")
```

## Testing

```bash
# Run all tests
python -m pytest test_score_calculator.py -v

# Run with the real local threat model (if ../threatmodels exists)
python -m pytest test_score_calculator.py -v -k "TestWithRealModel"
```

## Threat Models

Threat models are maintained in the [edamametechnologies/threatmodels](https://github.com/edamametechnologies/threatmodels) repository. Each model is a JSON file containing:

- **Metric definitions** with name, dimension, severity (1-5), and compliance tags
- **Detection logic** for platform-specific security checks
- **Remediation and rollback** instructions

The calculator fetches these models at runtime from GitHub (or can use local copies).

## License

Apache-2.0 -- see [LICENSE](LICENSE).
