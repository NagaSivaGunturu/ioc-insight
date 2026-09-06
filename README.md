# IOC Insight

### Turn an IOC into intelligence.

**IOC Insight** is an open-source IOC intelligence assessment tool for CTI, SOC, DFIR, and security analysts.

It queries multiple threat intelligence sources, normalizes and correlates the returned intelligence, and produces a concise, explainable assessment.

> **Collect. Normalize. Correlate. Assess. Explain.**

**Current Version:** `v0.1.0`

---

## What It Does

Given a single IOC, IOC Insight can provide:

- Threat classification
- Intelligence score
- Evidence supporting the assessment
- Threat actors
- Malware families
- MITRE ATT&CK techniques
- Tags
- Provider activity
- Community abuse reports
- First/last observed activity
- References

The goal is to reduce the manual effort required to check an indicator across multiple intelligence sources.

---

## Current Intelligence Sources

| Provider | Intelligence |
|---|---|
| **AlienVault OTX** | Threat pulses, threat actors, malware families, MITRE ATT&CK, tags, references and activity |
| **ThreatFox** | Malware-associated indicators, malware families, tags, references and activity |
| **AbuseIPDB** | IP reputation, community abuse reports and abuse activity |

Provider coverage depends on the IOC type. For example, AbuseIPDB is relevant to IP addresses.

---

## Installation

### Requirements

- Python `3.10+`
- Internet connectivity
- API credentials for the providers you want to query

### Clone

```bash
git clone https://github.com/NagaSivaGunturu/ioc-insight.git
cd ioc-insight
```

### Create a virtual environment

**Windows PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

IOC Insight supports two ways to provide API keys.

### Option 1 — Environment Variables (Recommended)

Environment variables keep API credentials outside project files.

**Windows PowerShell**

```powershell
$env:OTX_API_KEY="your_otx_api_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
$env:THREATFOX_API_KEY="your_threatfox_api_key"
```

| Provider | Environment Variable |
|---|---|
| OTX | `OTX_API_KEY` |
| AbuseIPDB | `ABUSEIPDB_API_KEY` |
| ThreatFox | `THREATFOX_API_KEY` |

If both an environment variable and a local configuration value are present, the **environment variable takes precedence**.

> PowerShell environment variables set with `$env:` apply to the current terminal session.

### Option 2 — Local Configuration

Create a local configuration file from the example:

**Windows**

```powershell
copy config\config.example.yaml config\config.yaml
```

**Linux / macOS**

```bash
cp config/config.example.yaml config/config.yaml
```

Then add your provider API keys:

```yaml
sources:
  otx:
    api_key: "YOUR_OTX_API_KEY"

  abuseipdb:
    api_key: "YOUR_ABUSEIPDB_API_KEY"

  threatfox:
    api_key: "YOUR_THREATFOX_API_KEY"
```

`config/config.yaml` is intentionally ignored by Git.

**Never commit real API keys or other secrets to the repository.**

---

## Usage

IOC Insight requires the IOC value and IOC type as command-line arguments.

### Basic Usage

```bash
python main.py --ioc <IOC_VALUE> --type <IOC_TYPE>
```

Example:

```bash
python main.py --ioc 101.200.193.211 --type IPv4
```

### Verbose Mode

```bash
python main.py --ioc 101.200.193.211 --type IPv4 --verbose
```

### Command-line Arguments

| Argument | Short | Required | Description |
|---|---|---:|---|
| `--ioc` | `-i` | Yes | IOC value to assess |
| `--type` | `-t` | Yes | IOC type |
| `--verbose` | `-v` | No | Enable verbose/debug logging |

### Supported IOC Types

IOC Insight currently accepts the IOC types supported by its IOC validator, including:

- `IPv4`
- `IPv6`
- `domain`
- `hostname`
- `url`
- `hash`
- `file`
- `auto` — automatic type detection, if supported by the validator

The exact intelligence returned depends on both the IOC type and provider coverage.

---

## Example Assessment

A typical IPv4 assessment looks like:

```text
IOC INTELLIGENCE ASSESSMENT

IOC
Value                : 185.100.212.141
Type                 : IPv4

Threat Assessment
Classification       : HIGH CONFIDENCE MALICIOUS

IOC Intelligence Score
Score                : 100/100

Intelligence Summary
This IPv4 indicator has been queried across 3 threat intelligence source(s).
Associated with threat actor(s): mdrfckr-ssh-backdoor
and malware family(s): Ssh brute-force.
The indicator has 13654 community abuse report(s).
Recent malicious activity has been observed within the last 90 days.

Evidence
✓ Threat intelligence pulse(s) available from OTX
✓ Reported indicator(s) available from ThreatFox
✓ Community abuse reports available from AbuseIPDB
✓ Known Threat Actor identified
✓ Known Malware Family identified
✓ Recent activity observed within 90 days
✓ IOC corroborated by multiple intelligence providers

Intelligence Activity
Providers Queried    : AbuseIPDB, OTX, ThreatFox
Providers Failed     : None
Community Reports    : 13654
```

The exact output depends on the intelligence returned by the providers.

---

## Provider Handling

IOC Insight distinguishes between **successful collection**, **successful collection with no relevant intelligence**, and **provider failure**.

Example:

```text
Providers Queried    : AbuseIPDB, ThreatFox
Providers Failed     : OTX
```

A failed provider is **not treated as negative intelligence** and is **not treated as a successful no-result**.

This means:

- A provider returning no matching intelligence is different from a provider that could not be queried.
- Authentication failures, network errors, API errors, and provider outages do not become "no intelligence found."
- Failed providers do not contribute intelligence, evidence, or corroboration to the assessment.
- The final output shows when an assessment is based on partial provider coverage.

---

## Intelligence Scoring

IOC Insight currently uses a transparent **heuristic scoring model**.

| Intelligence Signal | Weight |
|---|---:|
| ThreatFox reporting | +15 |
| OTX intelligence | +15 |
| AbuseIPDB community reports | +10 |
| Known threat actor | +20 |
| Known malware family | +15 |
| Recent activity | +15 |
| Multiple intelligence providers | +10 |

The score is capped at `100`.

### Classifications

| Score | Classification |
|---:|---|
| `90–100` | HIGH CONFIDENCE MALICIOUS |
| `70–89` | LIKELY MALICIOUS |
| `40–69` | SUSPICIOUS |
| `10–39` | LOW CONFIDENCE MALICIOUS |
| `<10` | INSUFFICIENT INTELLIGENCE |

> **Important:** The score is a transparent analytical heuristic, **not a mathematical probability of maliciousness**. A score of `100/100` does not mean 100% certainty.

---

## How It Works

```text
IOC
 │
 ├── OTX ───────────────┐
 ├── ThreatFox ─────────┤
 └── AbuseIPDB ─────────┤
                        ▼
              Provider Processors
                        │
                        ▼
                 Intel Models
                        │
                        ▼
                Intel Aggregator
                        │
                        ▼
                 Intel Analyzer
                        │
                        ▼
              Intelligence Assessment
                        │
                        ▼
                  Final Output
```

The processing flow is:

1. Accept an IOC from the command line.
2. Query the configured intelligence providers.
3. Process provider responses into a common intelligence model.
4. Aggregate and normalize the intelligence.
5. Track provider query failures separately.
6. Calculate the heuristic intelligence score.
7. Determine the classification.
8. Generate supporting evidence and summary.
9. Render the final assessment.

---

## Project Structure

```text
ioc-insight/
├── aggregator/
│   └── intel_aggregator.py
├── analyzers/
│   └── intel_analyzer.py
├── clients/
│   ├── abuseipdb_client.py
│   ├── otx_client.py
│   └── threatfox_client.py
├── config/
│   ├── config.example.yaml
│   ├── config.py
│   └── config_loader.py
├── models/
├── processors/
├── renderers/
├── utils/
├── main.py
├── requirements.txt
├── test_suite.py
├── version.py
├── LICENSE
└── README.md
```

---

## Development Mode

IOC Insight includes a development mode for reusing previously collected provider responses during development.

The setting is available in:

```text
config/config.py
```

When enabled, saved responses in:

```text
outputs/
```

can be reused instead of repeatedly querying external APIs.

This is primarily intended for development and testing of processing, aggregation, analysis, and rendering logic.

For normal live provider queries, disable development mode.

---

## Project Status

**IOC Insight `v0.1.0`** is the first public release.

Current scope includes:

- Multi-provider IOC intelligence collection
- Provider-specific response processing
- Intelligence normalization and aggregation
- Explainable heuristic scoring
- Threat classification
- Provider queried/failed status visibility
- Command-line IOC input
- Local development mode

The project is intentionally focused on the **single-IOC intelligence assessment workflow** at this stage.

---

## Contributing

Contributions, ideas, provider integrations, improvements to the assessment model, and bug reports are welcome.

If you find an issue or have an improvement in mind, please open an issue or pull request.

---

## Disclaimer

IOC Insight provides an analytical assessment based on the intelligence available to it and the rules implemented by the project.

It should **not** be treated as an authoritative determination that an indicator is malicious or benign.

Analysts should validate significant findings against the underlying intelligence sources and relevant organizational context.

---

## License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.

---

### IOC Insight

**Turn an IOC into intelligence.**

`Collect. Normalize. Correlate. Assess. Explain.`
