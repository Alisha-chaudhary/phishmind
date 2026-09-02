# PhishMind 🧠

### Agentic AI Phishing & BEC Investigation Engine

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

PhishMind is a modular Python-based phishing and Business Email Compromise (BEC) investigation engine that combines deterministic security analysis with AI-assisted SOC analyst reasoning.

The project explores a practical security operations question:

> What would a lightweight phishing investigation pipeline look like if email parsing, evidence extraction, authentication analysis, detection logic, threat intelligence, and AI analyst assistance were combined into one workflow?

PhishMind takes a `.eml` file, extracts security evidence, runs multiple investigation agents, evaluates the evidence using a deterministic risk engine, optionally enriches indicators with threat intelligence, and uses Gemini to generate an analyst-oriented explanation of the findings.

The deterministic risk engine remains authoritative.

**AI assists the analyst. It does not make the final security decision.**

---

## 🛠️ Built for

- SOC analyst learning
- Phishing and BEC investigation
- Defensive security research
- Security automation
- Agentic AI experimentation
- Portfolio and engineering practice

---

## 🚀 What it does

PhishMind takes a suspicious `.eml` file and runs it through a structured investigation pipeline:

- Parses email headers, body, and attachments
- Extracts URLs, domains, and public IP addresses
- Analyzes SPF, DKIM, and DMARC results
- Detects Reply-To / Return-Path mismatches
- Identifies potential sender/display-name spoofing
- Runs IOC, email, and URL analysis agents
- Correlates evidence using a deterministic risk engine
- Produces a verdict: `benign`, `suspicious`, `inconclusive`, or `malicious`
- Maps supported findings to MITRE ATT&CK techniques
- Optionally enriches indicators using threat-intelligence APIs
- Generates Markdown or HTML incident reports
- Optionally sends structured investigation evidence to Gemini
- Produces an AI-assisted SOC analyst explanation
- Keeps human approval required for remediation

---

## ⚡ Quick Start

### Clone the repository

```bash
git clone https://github.com/Alisha-chaudhary/phishmind.git
cd phishmind
```

### Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r Requirements.txt
```

### Analyze an email

```bash
python phishmind.py data/test_emails/01_credential_phishing.eml
```

### Run the full investigation

```bash
python phishmind.py data/test_emails/01_credential_phishing.eml --investigate
```

### Run with AI analyst assistance

```bash
python phishmind.py data/test_emails/01_credential_phishing.eml --ai
```

`--ai` automatically runs the deterministic investigation first and then generates an AI-assisted explanation using Gemini.

### Run threat-intelligence enrichment

```bash
python phishmind.py data/test_emails/01_credential_phishing.eml --enrich
```

### Generate an incident report

```bash
python phishmind.py data/test_emails/01_credential_phishing.eml \
    --investigate \
    --report html
```

### JSON output

```bash
python phishmind.py data/test_emails/01_credential_phishing.eml \
    --investigate \
    --json
```

### Run the test suite

```bash
pytest tests/ -v
```

---

## ⚡ Features

| Feature | Description |
|---|---|
| Email Parsing | Extracts headers, body, and attachments from .eml files |
| Evidence Extraction | Identifies URLs, domains, and public IP addresses |
| Authentication Analysis | SPF, DKIM, DMARC and sender consistency analysis |
| IOC Agent | Normalizes and inventories extracted indicators |
| Email Agent | Analyzes sender identity, BEC language and urgency |
| URL Agent | Examines URL structure and credential-harvesting indicators |
| Risk Engine | Deterministic evidence-based threat assessment |
| MITRE ATT&CK | Maps supported evidence to justified techniques |
| Threat Intelligence | VirusTotal, AbuseIPDB and urlscan.io enrichment |
| AI Analyst Assistance | Gemini-generated explanation of investigation findings |
| Human-in-the-Loop | Remediation always requires analyst approval |
| Reporting | Markdown and HTML incident reports |
| JSON Output | Machine-readable investigation results |
| Automated Tests | Regression tests for investigation scenarios |

---

## 🧩 Project Structure

```
phishmind/
├── phishmind.py
│
├── core/
│   ├── models.py
│   ├── email_parser.py
│   ├── evidence_extractor.py
│   └── auth_analyzer.py
│
├── agents/
│   ├── __init__.py
│   ├── orchestrator.py
│   ├── ioc_agent.py
│   ├── url_agent.py
│   ├── email_agent.py
│   ├── risk_agent.py
│   └── llm_agent.py
│
├── detection/
│   └── modern_threats.py
│
├── intelligence/
│   └── threat_intel.py
│
├── config/
│   ├── settings.py
│   └── .env.example
│
├── reports/
│   └── report_generator.py
│
├── tests/
│   └── test_pipeline.py
│
├── data/
│   └── test_emails/
│
├── README.md
└── Requirements.txt
```

---

## 🏗️ Architecture

PhishMind is designed as a staged investigation pipeline.

```
                         ┌─────────────────┐
                         │    .eml file    │
                         └────────┬────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │       CORE PARSING       │
                    │                          │
                    │ email_parser             │
                    │ evidence_extractor       │
                    │ auth_analyzer            │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │   InvestigationCase      │
                    │     Typed Evidence       │
                    └────────────┬─────────────┘
                                 │
                                 ▼
              ┌──────────────────────────────────────┐
              │         PARALLEL ANALYSIS             │
              │                                       │
              │ IOC Agent   Email Agent   URL Agent    │
              └──────────────────┬────────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │       RISK AGENT          │
                    │                          │
                    │ Deterministic verdict    │
                    │ Severity + confidence    │
                    │ MITRE mapping            │
                    │ Recommended action       │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
          ┌──────────────────┐     ┌────────────────────┐
          │ Threat Intel     │     │ Gemini AI Analyst  │
          │ --enrich         │     │ --ai               │
          └──────────────────┘     └─────────┬──────────┘
                                              │
                                              ▼
                                   Analyst Explanation
                                              │
                                              ▼
                                   Human Analyst Review
```

**Key architectural principle**

The deterministic risk agent remains authoritative.

Gemini does not replace the detection engine or decide whether an email is malicious.

Instead, the AI layer receives the structured investigation results and explains them in a format designed for a SOC analyst. This provides a separation between:

```
Detection
    ↓
Deterministic security logic
    ↓
Authoritative verdict
    ↓
AI-assisted explanation
    ↓
Human analyst decision
```

---

## 🔬 Investigation Pipeline

### Phase 1 — Email & Evidence Analysis

The core pipeline converts a raw `.eml` file into a structured `InvestigationCase`.

**Email Parser**

Extracts:
- Message headers
- Subject
- Sender information
- Reply-To
- Return-Path
- Message-ID
- Body content
- Attachments
- Attachment hashes

**Evidence Extractor**

Identifies:
- URLs
- Domains
- Public IP addresses
- Suspicious indicators

**Authentication Analyzer**

Examines authentication results reported by the receiving mail server:
- SPF
- DKIM
- DMARC
- Reply-To mismatch
- Return-Path mismatch
- Display-name spoofing

### 🤖 Phase 2 — Agentic Investigation

Three specialized analysis agents operate on the structured case:

| Agent | Responsibility |
|---|---|
| IOC Agent | Normalize and inventory indicators |
| Email Agent | Analyze sender identity, BEC language and urgency |
| URL Agent | Analyze URL structure and credential-harvesting patterns |

The agents produce structured findings which are passed to the risk engine.

### ⚖️ Risk Assessment

`risk_agent.py` is the only component responsible for assigning the final security verdict.

Possible outcomes include:

| Verdict | Meaning |
|---|---|
| benign | No meaningful malicious evidence identified |
| suspicious | Evidence suggests malicious intent but requires review |
| inconclusive | Evidence is insufficient for a confident verdict |
| malicious | Multiple strong indicators corroborate malicious activity |

Confidence is represented as `low`, `medium`, or `high` rather than presenting a misleading percentage such as "87% malicious".

The system also records reasoning and missing evidence alongside the verdict.

### 🌐 Threat Intelligence

When `--enrich` is supplied, PhishMind can enrich extracted indicators using:
- VirusTotal
- AbuseIPDB
- urlscan.io

Missing API keys, network failures, and rate limits degrade gracefully instead of crashing the investigation pipeline.

### 🧠 AI Analyst Assistance

PhishMind includes an optional Gemini-powered analyst assistance layer.

```bash
python phishmind.py suspicious.eml --ai
```

The AI receives the structured investigation results, not an unrestricted raw-email prompt.

The evidence package includes:
- Email metadata
- Authentication results
- Extracted evidence
- Agent findings
- Deterministic threat assessment
- Recommended action
- Threat-intelligence results

Gemini produces a concise analyst-oriented explanation containing:
- VERDICT SUMMARY
- STRONGEST INDICATORS
- ANALYST REASONING
- AUTHENTICATION ANALYSIS
- LIKELY ATTACK OBJECTIVE
- SOC RECOMMENDATION
- MISSING EVIDENCE

**AI safety design**

The AI layer is deliberately constrained:
- It cannot change the deterministic verdict
- It cannot invent indicators
- It cannot invent authentication results
- It cannot invent MITRE techniques
- It cannot automatically remediate an email
- Investigation continues even if the AI service fails
- Final remediation requires human analyst approval

This creates an analyst-assistance model rather than an autonomous remediation model.

---

## 🧪 Test Cases

PhishMind includes synthetic `.eml` fixtures designed to test important phishing-analysis edge cases.

| Test Case | Authentication | Expected Behaviour |
|---|---|---|
| Credential phishing | Authentication failure | Suspicious/malicious indicators should be detected |
| Compromised legitimate sender | SPF/DKIM/DMARC clean | BEC/payment-change behaviour should still be investigated |
| False-positive auth failure | SPF fail, DKIM/DMARC pass | Authentication failure alone should not automatically produce malicious |

The regression suite validates these behaviours automatically.

```bash
pytest tests/ -v
```

---

## 🧠 Why this project exists

A common phishing-analysis shortcut is:

```
SPF/DKIM/DMARC passes
        ↓
Email is trusted
```

That is not sufficient.

A compromised legitimate mailbox can pass SPF, DKIM and DMARC while still being used to conduct BEC or credential theft.

PhishMind therefore treats authentication as one piece of evidence, rather than the final verdict.

This distinction is central to the project's detection philosophy.

---

## 🐛 Engineering Lessons

PhishMind was developed iteratively, with bugs treated as part of the engineering process rather than silently patched away.

**False-positive spoof detection**

An early version of the authentication analyzer contained generic terms such as `hr`, `payroll`, `it support` inside the spoofed-brand detection list.

Because matching was performed using raw substring checks, an ordinary internal email such as "HR Team" could incorrectly trigger a spoofing finding.

**Fix**

The generic department terms were removed and matching was changed to use word-boundary logic.

**Lesson**

Detection logic must consider false-positive behaviour, not just whether it can detect an attack. This became an important design principle throughout PhishMind.

---

## 📊 Design Principles

1. **Authentication is evidence, not a verdict** — SPF/DKIM/DMARC results are incorporated into the overall assessment instead of being treated as a binary trust decision.
2. **Deterministic detection remains authoritative** — the rule-based risk engine provides the reproducible security verdict.
3. **AI explains rather than overrides** — Gemini operates as an analyst-assistance layer over structured findings.
4. **Evidence must justify MITRE mappings** — MITRE ATT&CK techniques are selected from a controlled catalog and require supporting evidence.
5. **Human approval is mandatory** — PhishMind investigates and recommends. It never automatically quarantines, blocks, or deletes an email.
6. **Graceful degradation** — optional services such as threat intelligence and AI assistance must not break the core investigation pipeline.

---

## ⚙️ Requirements

- Python 3.10+
- Linux / Kali Linux recommended
- Python virtual environment
- Internet connection for optional threat-intelligence and Gemini enrichment

Threat-intelligence API keys are optional.

Gemini API access is required only when using `--ai`.

API keys should be stored in environment variables and must never be committed to Git.

---

## 📁 Output

| Output | Purpose |
|---|---|
| Terminal output | Interactive SOC-style investigation summary |
| JSON | Machine-readable investigation results |
| Markdown | Standalone incident report |
| HTML | Browser-readable incident report |
| AI analysis | Analyst-oriented explanation when --ai is used |

---

## 🛠️ Built With

- Python
- Python email package
- Dataclasses
- Pytest
- Rich
- Jinja2
- Gemini API
- VirusTotal API
- AbuseIPDB API
- urlscan.io API
- MITRE ATT&CK concepts

---

## 🧠 Engineering Concepts Applied

This project was built as a hands-on security engineering exercise.

Key concepts include:
- Email header analysis
- SPF / DKIM / DMARC
- BEC detection
- IOC extraction and normalization
- Agent-based architecture
- Parallel analysis
- Deterministic risk scoring
- Confidence modelling
- MITRE ATT&CK mapping
- Threat-intelligence enrichment
- Structured data modelling with dataclasses
- API integration
- Graceful error handling
- Human-in-the-loop security automation
- Regression testing
- False-positive analysis
- AI-assisted security operations

---

## 🧭 Roadmap

- Attachment sandbox integration
- Static Office document analysis
- Macro/script detection
- Batch mailbox investigation
- GitHub Actions CI
- Additional threat-intelligence providers
- Analyst feedback loop
- Historical case tracking
- Expanded BEC detection patterns

---

## ⚠️ Disclaimer

PhishMind is intended for cybersecurity education, defensive research, and authorized security analysis.

Only analyze emails and systems you are authorized to investigate.

The author is not responsible for misuse of this project.

---

## 📄 License

This project is licensed under the MIT License.

Built by Alisha-chaudhary
