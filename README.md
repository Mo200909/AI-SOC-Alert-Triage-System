# AI SOC Alert Triage System

A local hybrid security alert triage prototype combining deterministic Python rules with a local Qwen3 8B language model. The system classifies synthetic security alerts, assigns severity levels, maps findings to MITRE ATT&CK techniques, and evaluates resistance to adversarial prompt injection.

In the current evaluation, the model's output matched the rules-only output on all 15 alerts, so no gain from the language model was measured.

## Features

- **Deterministic rule engine:** Uses 17 regular-expression rules to identify suspicious or potentially malicious activity.
- **Local AI analysis:** Runs Qwen3 8B through Ollama using Pydantic AI.
- **Structured output:** Validates classification, severity, confidence, technique, evidence, and recommended actions using Pydantic.
- **MITRE ATT&CK mapping:** Associates detected behavior with relevant technique identifiers.
- **Adversarial testing:** Evaluates model behavior against five prompt-injection test cases.
- **Local execution:** Uses a locally hosted model rather than requiring a hosted LLM API.

## Technology Stack

- Python 3.13
- Ollama
- Qwen3 8B
- Pydantic AI
- Pydantic
- Regular expressions
- MITRE ATT&CK

## How It Works

1. A synthetic security alert is loaded from `alerts.json`.
2. The deterministic rules engine searches the alert for known patterns.
3. The alert and rule findings are provided to Qwen3 as context.
4. Qwen3 produces a structured triage result.
5. The program compares both the rule output and model output against the expected labels.
6. Evaluation results are written to `evaluation_results.json`.

The model receives the rules engine's output as context. This is a comparison between deterministic rules and AI-assisted triage with rule context, not a comparison against a separately tested pure-AI baseline.

## Evaluation Results

The current 15-alert evaluation (`evaluation_results.json`) reported the following results:

| Metric | Rules only | Qwen3 8B (with rule context) |
|---|---|---|
| Classification | 14/15 (93%) | 14/15 (93%) |
| Severity | 12/15 (80%) | 12/15 (80%) |
| MITRE ATT&CK technique | 14/15 (93%) | 14/15 (93%) |
| All three fields correct | 12/15 (80%) | 12/15 (80%) |

Qwen3 output was identical to the rules-only output on all 15 alerts. These results show no measured improvement from the model, and they come from a small synthetic test set. They should not be interpreted as production detection performance.

### Misses

| Alert | Expected | Result | Issue |
|---|---|---|---|
| alert_005 | SUSPICIOUS / HIGH / T1057 | SUSPICIOUS / MEDIUM / T1057 | Severity one level low |
| alert_010 | MALICIOUS / CRITICAL / T1547.001 | MALICIOUS / HIGH / T1547.001 | Severity one level low |
| alert_012 | SUSPICIOUS / MEDIUM / T1562.001 | BENIGN / LOW / NONE | Missed detection (McAfee scheduled-task deletion), rated at 0.95 confidence |

### Reproducibility Check (Nov 25, 2026)

The full evaluation was re-run. Accuracy metrics were unchanged (14/15, 12/15, 14/15, 12/15), and Qwen3 8B still matched the rules engine on every field.

Confidence was not stable between runs. In the earlier run, confidence ranged from 0.7 to 0.95. In the latest run, it was 0.95 on all 15 alerts, including all 3 errors. The model's confidence score is not calibrated and should not be used to prioritize alerts.

## Adversarial Testing

Five prompt-injection test cases were evaluated (`adversarial_results.json`).

| Test outcome | Count |
|---|---|
| Defended | 3/5 |
| Vulnerable | 2/5 |
| Defense rate | 60% |

Observed weaknesses included reasoning poisoning and encoding evasion. These tests provide an initial assessment, not comprehensive proof of prompt-injection resistance.

## Known Limitations

- Evaluation uses only 15 synthetic alerts.
- The model receives rule-engine findings as context, and its output matched the rules-only output on every alert, so no benefit from the model was measured.
- A separate pure-AI baseline has not been established.
- The McAfee scheduled-task deletion alert (alert_012) is a known detection gap in the original rule set, and the model did not correct it.
- Severity was one level low on two alerts (alert_005, alert_010).
- Model confidence is not calibrated: the latest run reported 0.95 on all 15 alerts, including all 3 errors, and scores changed between runs.
- Prompt-injection defenses are incomplete.
- The system has not been integrated with a live SIEM or validated against real production telemetry.
- Regular-expression rules can miss variations in alert wording and may produce false positives.

## Project Files

- `main.py` — Rule engine, local model integration, evaluation loop, and adversarial prompt-injection tests.
- `alerts.json` — Synthetic alerts and expected classifications.
- `evaluation_results.json` — Per-alert rule and model evaluation results.
- `adversarial_results.json` — Adversarial test results.

## Setup

### Prerequisites

- Python 3.13
- Ollama installed and running
- Qwen3 8B downloaded through Ollama

Download the model:

```
ollama pull qwen3:8b
```

Install the Python dependency:

```
pip install pydantic-ai
```

Run the evaluation from the project directory:

```
python main.py
```

The script reads `alerts.json`, evaluates the alerts, prints accuracy metrics, and writes `evaluation_results.json` and `adversarial_results.json`.

## Project Goal

This project explores how deterministic detection rules and locally hosted language models can complement one another during security alert triage. It also examines the limits of structured model output and prompt-injection defenses.

The current implementation is an experimental portfolio project, not a production-ready SOC detection or response system.
