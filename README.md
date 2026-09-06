**# IOC Insight**

**### Turn an IOC into intelligence.**

**Current Version:** v0.1.0

IOC Insight is an open-source **\*\*IOC intelligence assessment tool\*\*** designed to help Cyber Threat Intelligence (CTI), SOC, DFIR, and security analysts quickly understand the significance of an indicator without manually reviewing multiple intelligence sources one by one.

Instead of simply returning raw enrichment results, IOC Insight aggregates intelligence from multiple sources, normalizes the results, correlates the available evidence, evaluates the indicator, and produces a concise, explainable intelligence assessment.

\> **\*\*The goal isn't to replace existing CTI platforms. It's to make intelligence from multiple sources easier to interpret and act on.\*\***

\---

**## Why IOC Insight?**

Investigating a single IOC can quickly become a repetitive workflow:

\`\`\`text

IOC

 │

 ├── Tool-1

 │

 ├── Tool-2

 │

 ├── Tool-3

 │

 └── Internal intelligence

       │

       ▼

  Analyst compares results

       │

       ▼

  Analyst interprets evidence

       │

       ▼

  Analyst determines significance

       │

       ▼

  Analyst documents the conclusion

\`\`\`

The problem isn't necessarily a lack of intelligence.

The problem is **\*\*fragmented intelligence and analyst effort required to interpret it\*\***.

IOC Insight is designed to reduce that friction:

The result is not just:

\> "This IOC was found."

It is:

\> **\*\*"This is what the available intelligence tells us, how strong the evidence is, and why."\*\***

\---

**# What Makes IOC Insight Different?**

IOC Insight is **\*\*not intended to replace platforms such as VirusTotal, MISP, AbuseIPDB, or other commercial/open-source intelligence platforms\*\***.

Those platforms solve broader and sometimes different problems.

IOC Insight focuses on a narrower analyst workflow:

\> **\*\*Given an IOC, what does the available intelligence collectively tell me, and how strongly should I consider it?\*\***

**### 1. From enrichment to assessment**

Traditional enrichment often produces individual observations:

\`\`\`text

ThreatFox → Indicator found

OTX       → Pulse found

AbuseIPDB → Abuse reports found

\`\`\`

IOC Insight consolidates those observations into an assessment:

\`\`\`text

Threat Assessment

────────────────────────────────────────

Classification : 🔴 HIGH CONFIDENCE MALICIOUS

IOC Intelligence Score

────────────────────────────────────────

Score           : ████████████████████████████████████████ 100/100

\`\`\`

\---

**### 2. Evidence-backed conclusions**

An assessment should answer:

\> **\*\*Why did the tool reach this conclusion?\*\***

IOC Insight exposes the supporting evidence:

\`\`\`text

Evidence

────────────────────────────────────────

✓ Reported indicator available from ThreatFox

✓ Threat intelligence pulse available from OTX

✓ Community abuse reports available from AbuseIPDB

✓ Known Threat Actor identified

✓ Known Malware Family identified

✓ Recent activity observed

✓ IOC corroborated by multiple intelligence providers

\`\`\`

The scoring model is deliberately transparent rather than being a black-box verdict. It is a **heuristic model**, not a definitive determination of maliciousness.

\---

**### 3. Source-agnostic intelligence model**

Different CTI platforms return intelligence in very different formats.

IOC Insight converts provider-specific responses into a common intelligence representation:

This allows additional intelligence sources to be integrated without redesigning the entire assessment pipeline.

\---

**### 4. Reduce analyst cognitive load**

The purpose isn't to eliminate analyst judgment.

It is to reduce the mechanical work required before an analyst can exercise that judgment.

The analyst can then decide whether deeper investigation is warranted.

\---

**# Example Output**

For an investigated IPv4 address, IOC Insight currently produces an assessment similar to:

\`\`\`text

\================================================================================

                          IOC INTELLIGENCE ASSESSMENT

\================================================================================

IOC

\--------------------------------------------------------------------------------

Value                : X.X.X.X

Type                 : IPv4

Threat Assessment

\--------------------------------------------------------------------------------

Classification       : 🔴 HIGH CONFIDENCE MALICIOUS

IOC Intelligence Score

\--------------------------------------------------------------------------------

Score                : ████████████████████████████████████████ 100/100

Intelligence Summary

\--------------------------------------------------------------------------------

This IPv4 indicator has been queried across 3 threat intelligence

source(s). Associated with threat actor(s): Cobalt, Earth Alux and malware

family(s): Asyncrat, Clearfake, Cobalt Strike, Formbook, Iclickfix, Qilin,

Ransomhub, Unknown stealer, Xworm. The indicator has 2 community abuse

report(s). Recent malicious activity has been observed within the last 90 days.

Evidence

\--------------------------------------------------------------------------------

✓ Reported indicator(s) available from ThreatFox

✓ Threat intelligence pulse(s) available from OTX

✓ Community abuse reports available from AbuseIPDB

✓ Known Threat Actor identified

✓ Known Malware Family identified

✓ Recent activity observed within 90 days

✓ IOC corroborated by multiple intelligence providers

Intelligence Findings

\--------------------------------------------------------------------------------

Threat Actors        : Cobalt, Earth Alux

Malware Families     : Asyncrat, Clearfake, Cobalt Strike, Formbook, Iclickfix,

                       Qilin, Ransomhub, Unknown stealer, Xworm

MITRE ATT&CK         : T1027, T1041, T1055, T1055.001, T1056.001, T1059.001,

                       T1071, T1071.001, T1090, T1105 ... (+11 more)

Tags                 : 32-bit, ALIBABA-CN-NET, Amadey, apesar da, APT, apt

                       associados, apt28, apt29, archive, arm ... (+138 more)

Intelligence Activity

\--------------------------------------------------------------------------------

Providers            : AbuseIPDB, OTX, ThreatFox

Community Reports    : 2

First Seen           : 2022-10-11

Last Seen            : 2026-08-01

References

\--------------------------------------------------------------------------------

• https\://...

• https\://...

• https\://...

... (+182 more)

\`\`\`

The exact output depends on the intelligence returned by the configured providers.

\---

**# Current Intelligence Sources**

IOC Insight currently integrates:

\| Source | Purpose |

\|---|---|

\| **\*\*AlienVault OTX\*\*** | Threat pulses, threat actors, malware families, MITRE ATT&CK, tags, references and activity |

\| **\*\*ThreatFox\*\*** | Malware-associated indicators, malware families, tags, references and activity |

\| **\*\*AbuseIPDB\*\*** | IP reputation, abuse reports, reporting activity and abuse categories |

The architecture is intentionally designed so additional sources can be added later.



**## Provider Handling**

A provider that fails to respond successfully is **not treated as negative intelligence** and is **not treated as a successful no-result**.

IOC Insight distinguishes between:

- **Provider queried successfully and returned intelligence**
- **Provider queried successfully but returned no relevant intelligence**
- **Provider query failed or was unavailable**

Provider status is surfaced in the assessment output so analysts can see whether the final assessment is based on complete or partial collection.

Example:

```text
Providers Queried    : AbuseIPDB, ThreatFox
Providers Failed     : OTX
```

A failed provider therefore does **not** mean the IOC is clean or unknown in that provider. It means IOC Insight was unable to successfully collect intelligence from that provider during that run.

This distinction is important because **failed collection must never be interpreted as “no intelligence found.”**


**# Intelligence Processing Pipeline**

**## 1. IOC**

The investigation begins with a single IOC.

Current implementation:

\`\`\`python

IOC(

    ioc\_type="IPv4",

    ioc\_value="X.X.X.X"

)

\`\`\`

The IOC model currently represents:

\- IOC type

\- IOC value

The initial version focuses on **\*\*single-IOC investigation\*\***.

\---

**## 2. Collection**

Each provider has a dedicated client.

\`\`\`text

OTXClient

ThreatFoxClient

AbuseIPDBClient

\`\`\`

Clients are responsible only for communicating with the external provider APIs and returning the raw response.

They do not perform CTI analysis.

\---

**## 3. Processing**

Provider-specific processors convert raw API responses into the common \`Intel\` model.

\`\`\`text

OTX JSON

   ↓

OTXProcessor

   ↓

Intel

ThreatFox JSON

   ↓

ThreatFoxProcessor

   ↓

Intel

AbuseIPDB JSON

   ↓

AbuseIPDBProcessor

   ↓

Intel

\`\`\`

This isolates provider-specific API structures from the rest of the application.

\---

**## 4. Aggregation**

The \`IntelAggregator\` combines the individual provider intelligence objects.

It currently handles:

\- First Seen

\- Last Seen

\- Threat Actors

\- Malware Families

\- Campaigns

\- MITRE ATT&CK

\- Tags

\- Infrastructure Roles

\- Targeted Sectors

\- References

\- Providers

\- Community Reports

It also normalizes string-based intelligence by:

\- Removing empty values

\- Normalizing whitespace

\- Performing case-insensitive deduplication

\- Preserving a cleaner representation

\- Sorting the final results

\---

**## 5. Analysis**

The \`IntelAnalyzer\` evaluates the consolidated intelligence.

The current V1 assessment considers factors including:

\| Intelligence Signal | Current Weight |

\|---|---:|

\| ThreatFox reporting | +15 |

\| OTX intelligence | +15 |

\| AbuseIPDB community reports | +10 |

\| Known threat actor | +20 |

\| Known malware family | +15 |

\| Recent activity | +15 |

\| Multiple intelligence providers | +10 |

The resulting score is capped at 100.

**### Current classifications**

\`\`\`text

90–100   HIGH CONFIDENCE MALICIOUS

70–89    LIKELY MALICIOUS

40–69    SUSPICIOUS

10–39    LOW CONFIDENCE MALICIOUS

<10      INSUFFICIENT INTELLIGENCE

\`\`\`

**### Important note**

The score is a **\*\*transparent analytical heuristic\*\***, not a mathematically proven probability of maliciousness.

A score of \`100/100\` does not mean "100% certainty."

It means the current assessment rules identified a maximum-strength combination of supported intelligence signals.

The scoring model is intentionally explainable and can evolve as the project matures.

\---

**# Intelligence Assessment Model**

The final assessment is built around several questions an analyst typically needs answered:

**### What is the IOC?**

\`\`\`text

IOC

Value : ...

Type  : IPv4

\`\`\`

**### What is our assessment?**

\`\`\`text

Threat Assessment

Classification : HIGH CONFIDENCE MALICIOUS

\`\`\`

**### How strong is the assessment?**

\`\`\`text

IOC Intelligence Score

Score : 100/100

\`\`\`

**### What does the intelligence tell us?**

\`\`\`text

Intelligence Summary

...

\`\`\`

**### Why did we reach that conclusion?**

\`\`\`text

Evidence

✓ ThreatFox reporting

✓ OTX intelligence

✓ Malware association

✓ Recent activity

...

\`\`\`

**### What intelligence was discovered?**

\`\`\`text

Intelligence Findings

Threat Actors

Malware Families

MITRE ATT&CK

Tags

\`\`\`

**### What activity exists?**

\`\`\`text

Intelligence Activity

Providers

Community Reports

First Seen

Last Seen

\`\`\`

**### Where can the analyst validate it?**

\`\`\`text

References

...

\`\`\`

\---



**# Why Would an Analyst Use It?**

IOC Insight is designed for situations where an analyst needs a quick initial assessment of an indicator.

For example:

\> An analyst receives an IP address from an alert, phishing investigation, threat report, suspicious email, or threat-hunting activity.

Instead of manually opening multiple intelligence sources and comparing results, the analyst can obtain a consolidated assessment containing:

\- Threat classification

\- Intelligence score

\- Evidence

\- Threat actors

\- Malware families

\- MITRE ATT&CK techniques

\- Tags

\- Intelligence providers

\- First/last observed activity

\- Community reports

\- References

The analyst can then decide whether deeper investigation is warranted.

**### The intended value is simple:**

\> **\*\*Reduce the time between receiving an IOC and understanding its significance.\*\***

\---



**# Installation**

**## Prerequisites**

\- Python 3.10+

\- Internet connectivity

\- API credentials for the configured intelligence providers

\---

**## Clone the repository**

\`\`\`bash

git clone https\://github.com/\<YOUR-USERNAME>/ioc-insight.git

cd ioc-insight

\`\`\`

\---

**## Create a virtual environment**

**### Windows**

\`\`\`powershell

python -m venv .venv

.venv\Scripts\Activate.ps1

\`\`\`

**### Linux/macOS**

\`\`\`bash

python3 -m venv .venv

source .venv/bin/activate

\`\`\`

\---

**## Install dependencies**

\`\`\`bash

pip install -r requirements.txt

\`\`\`

\---

**# Configuration**

IOC Insight supports two methods for supplying provider API keys.

## Option 1 — Environment Variables (Recommended)

Environment variables are recommended because API keys remain outside the project files.

### Windows PowerShell

```powershell
$env:OTX_API_KEY="your_otx_api_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
$env:THREATFOX_API_KEY="your_threatfox_api_key"
```

### API key precedence

If both an environment variable and a local configuration value are present, **the environment variable takes precedence**.

The supported environment variables are:

| Provider | Environment Variable |
|---|---|
| OTX | `OTX_API_KEY` |
| AbuseIPDB | `ABUSEIPDB_API_KEY` |
| ThreatFox | `THREATFOX_API_KEY` |

## Option 2 — Local `config/config.yaml`

Create a local configuration file from the example:

### Windows

```powershell
copy config\config.example.yaml config\config.yaml
```

### Linux/macOS

```bash
cp config/config.example.yaml config/config.yaml
```

Then add your API keys to the local `config/config.yaml`.

Example:

```yaml
sources:
  otx:
    api_key: "YOUR_OTX_KEY"

  abuseipdb:
    api_key: "YOUR_ABUSEIPDB_KEY"

  threatfox:
    api_key: "YOUR_THREATFOX_KEY"
```

### Important security note

- `config/config.yaml` is ignored by Git.
- `.env` files are ignored by Git.
- Never commit real API keys.
- Check `git status` before committing changes.

**Recommended:** Use environment variables for normal usage and keep `config/config.yaml` only as a local development option.

---

**# Running IOC Insight**

IOC Insight requires the IOC value and IOC type as command-line input.

```bash
python main.py --ioc <IOC_VALUE> --type <IOC_TYPE>
```

Example:

```bash
python main.py --ioc 101.200.193.211 --type IPv4
```

## Command-line arguments

| Argument | Required | Description |
|---|---|---|
| `--ioc` / `-i` | Yes | IOC value to assess |
| `--type` / `-t` | Yes | IOC type |
| `--verbose` / `-v` | No | Enable verbose debug logging |

Example with verbose logging:

```bash
python main.py --ioc 101.200.193.211 --type IPv4 --verbose
```

### Supported IOC types

IOC Insight currently accepts the IOC types supported by the IOC validator, including common types such as:

- `IPv4`
- `IPv6`
- `domain`
- `hostname`
- `url`
- `hash`
- `file`
- `auto` (automatic type detection, if supported by the validator)

If you use `auto`, the validator attempts to determine the IOC type from the supplied value.

The exact provider coverage may vary by IOC type. For example, AbuseIPDB is only queried for IP addresses.

---

**# Development Mode**
**# Development Mode**

IOC Insight currently supports a development mode that allows previously collected provider responses to be reused.

In:

\`\`\`text

config/config.py

\`\`\`

\`\`\`python

DEVELOPMENT\_MODE = True

\`\`\`

When development mode is enabled, the application reads previously saved responses from:

\`\`\`text

outputs/

\`\`\`

This allows development of processors, aggregation, analysis, and rendering without repeatedly calling external APIs.

Set:

\`\`\`python

DEVELOPMENT\_MODE = False

\`\`\`

when you want the application to query the configured providers again.





\---

**# Disclaimer**

IOC Insight provides an **\*\*analytical assessment based on the intelligence available to it and the rules implemented by the project\*\***.

It should not be treated as an authoritative determination that an indicator is malicious or benign.

Analysts should validate significant findings against the underlying intelligence sources and relevant organizational context.

A high score indicates strong supporting evidence according to the current assessment model; it does not represent a mathematical probability of maliciousness.

\---

**# License**

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

**# Author**

Created and maintained by **Naga Siva Gunturu**.


**# Project Status**

**IOC Insight v0.1.0** is the first public release and represents the initial implementation of the IOC intelligence assessment workflow.

The current scope includes:

- Multi-provider IOC intelligence collection
- Provider-specific response processing
- Intelligence normalization and aggregation
- Explainable heuristic scoring
- Classification based on the available intelligence
- Provider queried/failed status visibility
- Command-line IOC input
- Local development mode for saved provider responses

The scoring and classification model should be treated as **heuristic intelligence assessment**, not as an authoritative or final security verdict.

Future improvements may expand provider coverage, IOC-type support, scoring logic, reporting, and analyst workflows.


**## IOC Insight**

\> **\*\*Turn an IOC into intelligence.\*\***

**\*\*Collect. Normalize. Correlate. Assess. Explain.\*\***