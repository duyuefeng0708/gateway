# PII Detection Benchmark Results

Benchmark date: 2026-04-20
Dataset: `eval/sample_benchmark.jsonl` (5 entries, 7 ground-truth spans)
Hardware: Apple M5 laptop, 32 GB unified memory
Server: llama.cpp / LM Studio on port 8787

## Recall Targets (Phase 1 Plan)

| Target | Requirement | Kill Criterion |
|--------|-------------|----------------|
| Explicit PII recall | >= 90% | < 60% |
| Implicit PII recall | >= 70% | < 60% |

---

## Model Comparison

### Gemma-4-26B-A4B-it-uncensored (Q4_K_M, 16.8 GB)

Tier 3 deep-scan candidate.

**Accuracy**

| Category | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| Overall | 0.875 | **1.000** | 0.933 |
| Explicit PII | 0.857 | **1.000** | 0.923 |
| Implicit PII | 1.000 | **1.000** | 1.000 |

**Latency**

| Metric | Value |
|--------|-------|
| Avg wall-clock | ~86s |
| Prompt throughput | ~414 tok/s |
| Gen throughput | ~26 tok/s |

**Recall targets: PASS (both)**

**Per-entry breakdown**

| # | Prompt | Expected | Detected | TP | FP | FN |
|---|--------|----------|----------|----|----|-----|
| 0 | `Please email alice@example.com about the meeting.` | 1 | 1 | 1 | 0 | 0 |
| 1 | `My name is John Smith and my SSN is 123-45-6789.` | 2 | 2 | 2 | 0 | 0 |
| 2 | `Call me at (555) 867-5309 or reach me at bob.jones@work.org.` | 2 | 2 | 2 | 0 | 0 |
| 3 | `The CEO of Acme Corp disclosed the quarterly earnings...` | 2 | 2 | 2 | 0 | 0 |
| 4 | `The weather in Paris will be sunny this weekend...` | 0 | 1 | 0 | 1 | 0 |

Notes:
- Perfect recall across all 7 ground-truth spans (7/7 TP, 0 FN).
- 1 false positive: detected "Paris" as LOCATION (debatable, not labeled in ground truth).
- Correctly identified implicit PII ("The CEO" as PERSON, implicit=true, confidence=0.8).
- Slow due to thinking mode (~1800 reasoning tokens before output).

---

### Gemma-4-E4B-Uncensored-HauhauCS-Aggressive (Q6_K_P, 6.25 GB)

Tier 2 fast pre-scan candidate.

**Accuracy**

| Category | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| Overall | 0.714 | 0.714 | 0.714 |
| Explicit PII | 0.714 | 0.833 | 0.769 |
| Implicit PII | 1.000 | **0.000** | 0.000 |

**Latency**

| Metric | Avg | P50 | Min | Max |
|--------|-----|-----|-----|-----|
| Wall-clock | **3.0s** | 3.7s | 1.7s | 4.0s |

**Recall targets: FAIL (both)**
- Explicit PII recall: 83.3% (target >= 90%)
- Implicit PII recall: 0.0% (KILL CRITERION: < 60%)

**Per-entry breakdown**

| # | Prompt | Expected | Detected | TP | FP | FN |
|---|--------|----------|----------|----|----|-----|
| 0 | `Please email alice@example.com about the meeting.` | 1 | 1 | 1 | 0 | 0 |
| 1 | `My name is John Smith and my SSN is 123-45-6789.` | 2 | 2 | 1 | 1 | 1 |
| 2 | `Call me at (555) 867-5309 or reach me at bob.jones@work.org.` | 2 | 2 | 2 | 0 | 0 |
| 3 | `The CEO of Acme Corp disclosed the quarterly earnings...` | 2 | 1 | 1 | 0 | 1 |
| 4 | `The weather in Paris will be sunny this weekend...` | 0 | 1 | 0 | 1 | 0 |

Notes:
- ~30x faster than the 26B model (3s vs 86s avg).
- Byte-offset errors on SSN detection caused a match failure despite correct text extraction.
- Completely missed implicit PII ("CEO" as PERSON).
- Suitable for Tier 2 fast pre-scan; requires Tier 3 escalation for implicit and low-confidence spans.

---

## Head-to-Head Summary

| | Gemma-4-E4B (7.5B) | Gemma-4-26B-A4B |
|---|---|---|
| **Explicit recall** | 83.3% FAIL | 100% PASS |
| **Implicit recall** | 0% FAIL | 100% PASS |
| **Overall F1** | 0.714 | 0.933 |
| **Avg latency** | **3.0s** | ~86s |
| **Speedup** | **~30x** | baseline |
| **VRAM** | 5.8 GiB | 15.4 GiB |
| **Tier role** | Tier 2 fast pre-scan | Tier 3 deep scan |

## Cloud GPU Throughput Estimates (Gemma-4-26B-A4B)

| GPU | Quant | Gen tok/s | Est. request time | $/hr (spot) |
|-----|-------|-----------|-------------------|-------------|
| RTX PRO 6000 Blackwell 96GB | Q4_K_M | ~181 | ~11s | - |
| RTX 4090 24GB | Q4/Q6 | ~150 | ~13s | - |
| H100 80GB | BF16 | ~120 | ~17s | $0.80 |
| A100 80GB | FP8 | ~80 | ~25s | $0.45 |
| L4 24GB | Q4 | ~50 | ~40s | $0.98 |
| Apple M5 (laptop) | Q4_K_M | 26 | ~77s | - |

Request time assumes ~2000 token thinking budget per PII detection call.

## Conclusion

The tiered architecture is validated:
1. **Tier 1 (regex)** handles emails, SSNs, phones at sub-millisecond latency.
2. **Tier 2 (E4B)** provides fast LLM pre-scan at ~3s but misses implicit PII and has offset errors.
3. **Tier 3 (26B)** achieves perfect recall but is slow on-device; cloud GPU deployment (H100/A100) would bring latency to an acceptable 17-25s range.

Auto-escalation from Tier 2 to Tier 3 (on confidence < 0.7 or zero detections on long prompts) is critical to meeting recall targets.
