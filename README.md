# AI-SOC-Alert-Triage-System

Local hybrid AI + deterministic system for classifying security alerts.

## Stack

- Qwen3 8B (via Ollama)
- Pydantic AI (structured output)
- Deterministic regex rules (17 rules)
- Python 3.13

## Usage

```bash
pip install pydantic-ai
python main.py
```

## Results

**Qwen3 with rule context, evaluated on 15 synthetic alerts:**

- **Classification accuracy:** 86% (13/15)
- **Severity accuracy:** 80% (12/15)
- **Technique accuracy:** 80% (12/15)
- **Joint accuracy:** 73% (11/15; all three outputs correct)

**Rules engine baseline:**

- Classification accuracy: 93% (14/15)
- Severity accuracy: 80% (12/15)
- Technique accuracy: 86% (13/15)
- Joint accuracy: 73% (11/15)

The rules engine matched Qwen3 with rule context on joint accuracy and performed better on classification and technique identification in this evaluation. A separate pure-AI baseline has not been established.

### Adversarial Testing

- **Injections defended:** 3/5 (60%)
- **Vulnerabilities observed:** Reasoning poisoning and encoding evasion

## How It Works

1. An alert enters the system.
2. Deterministic rules run first.
3. Rule results and alert text are passed to Qwen3.
4. Qwen3 produces structured output.
5. Pydantic validates the output schema.

## Key Insight

Deterministic rules provide predictable pattern matching, while the language model adds contextual analysis. The current evaluation does not establish that this approach outperforms a pure-AI system.

## Limitations

- Only 15 synthetic alerts; not evaluated on a production dataset.
- Technique identification remains imperfect (3/15 mismatches).
- Defense-evasion detection is incomplete.
- No real SIEM integration.
- Prompt-injection defenses failed in 2 of 5 adversarial tests.
- Evaluation results are limited by the small test set.

## Files

- `main.py` — Rules engine and Qwen agent
- `alerts.json` — 15-alert test dataset
- `adversarial_test.py` — Prompt-injection tests
- `evaluation_results_fixed.json` — Main evaluation metrics
- `adversarial_results.json` — Security testing results
