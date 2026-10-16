# AI SOC Alert Triage System

A local hybrid security alert triage prototype combining deterministic Python rules with a local Qwen3 8B language model. The system classifies synthetic security alerts, assigns severity levels, maps findings to MITRE ATT&CK techniques, and evaluates resistance to adversarial prompt injection.

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
6. Evaluation results are written to `evaluation_results_fixed.json`.

The model receives the rules engine's output as context. This is a comparison between deterministic rules and AI-assisted triage with rule context, not a comparison against a separately tested pure-AI baseline.

## Evaluation Results

The current 15-alert evaluation reported the following Qwen3 results:

| Metric | Correct | Accuracy |
|---|---:|---:|
| Classification | 13/15 | 86% |
| Severity | 12/15 | 80% |
| MITRE ATT&CK technique | 12/15 | 80% |
| All three fields correct | 11/15 | 73% |

These results are from a small synthetic test set and should not be interpreted as production detection performance.

### Adversarial Testing

Five prompt-injection test cases were evaluated.

| Test outcome | Count |
|---|---:|
| Defended | 3/5 |
| Vulnerable | 2/5 |
| Defense rate | 60% |

Observed weaknesses included reasoning poisoning and encoding evasion. These tests provide an initial assessment, not comprehensive proof of prompt-injection resistance.

## Known Limitations

- Evaluation uses only 15 synthetic alerts.
- The model receives rule-engine findings as context; a separate pure-AI baseline has not been established.
- The McAfee scheduled-task deletion alert is a known detection gap in the original rule set.
- Technique and severity assignments are not consistently correct.
- Prompt-injection defenses are incomplete.
- The system has not been integrated with a live SIEM or validated against real production telemetry.
- Regular-expression rules can miss variations in alert wording and may produce false positives.

## Project Files

- `main.py` — Rule engine, local model integration, and evaluation loop.
- `alerts.json` — Synthetic alerts and expected classifications.
- `adversarial_test.py` — Adversarial prompt-injection tests.
- `evaluation_results_fixed.json` — Per-alert rule and model evaluation results.
- `adversarial_results.json` — Adversarial test results.

## Setup

### Prerequisites

- Python 3.13
- Ollama installed and running
- Qwen3 8B downloaded through Ollama

Download the model:

```bash
ollama pull qwen3:8b
```

Install the Python dependency:

```bash
pip install pydantic-ai
```

Run the evaluation from the project directory:

```bash
python main.py
```

The script reads `alerts.json`, evaluates the alerts, prints accuracy metrics, and writes `evaluation_results_fixed.json`.

## Project Goal

This project explores how deterministic detection rules and locally hosted language models can complement one another during security alert triage. It also examines the limits of structured model output and prompt-injection defenses.

The current implementation is an experimental portfolio project, not a production-ready SOC detection or response system.
