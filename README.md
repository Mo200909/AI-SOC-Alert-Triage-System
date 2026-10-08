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
- **Classification accuracy:** 86% (13/15)
- **Severity accuracy:** 80% (12/15)
- **Technique accuracy:** 80% (12/15)
- **All three correct:** 73% (11/15)

### Adversarial Testing
- **Injections defended:** 3/5 (60%)
- **Vulnerabilities:** Reasoning poisoning, encoding evasion
- **Conclusion:** Hybrid approach (rules + AI) outperforms pure AI (33% → 73%)

## How It Works
1. Alert enters system
2. Deterministic rules run first (fast, predictable)
3. Rules + alert fed to Qwen3
4. Qwen outputs structured JSON
5. Pydantic validates schema

## Key Insight
AI alone is unreliable. Rules alone are rigid. Hybrid respects security while leveraging AI reasoning.

## Limitations
- Only 15 synthetic alerts (not production dataset)
- Technique identification still weak (2/15 mismatches)
- Defense evasion detection incomplete
- No real SIEM integration


## Files
- `main.py` — Rules engine + Qwen agent
- `alerts.json` — 15-alert test dataset
- `adversarial_test.py` — Prompt injection tests
- `evaluation_results_fixed.json` — Main evaluation metrics
- `adversarial_results.json` — Security testing results
