#!/usr/bin/env python3
"""PII detection benchmark runner using llama.cpp against local GGUF models.

Mirrors the entity-level matching logic from gateway's eval.rs:
  - Overlap-based matching (partial overlap counts)
  - Same PII type required
  - Greedy one-to-one matching
  - Separate metrics for explicit vs implicit PII

Recall targets (from Phase 1 plan):
  - Explicit PII recall >= 90%
  - Implicit PII recall >= 70%
"""

import json
import os
import subprocess
import sys
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

MODEL_PATH = Path.home() / "AI" / "gemma-4-26B-A4B-it-uncensored-Q4_K_M.gguf"
BENCHMARK_PATH = Path(__file__).parent / "sample_benchmark.jsonl"
SERVER_URL = "http://127.0.0.1:8787"

SYSTEM_PROMPT = """You are a PII detection engine. Given user text, identify all personally identifiable information (PII).

Return ONLY a JSON array (no markdown, no explanation). Each element must be:
{"type": "<TYPE>", "start": <int>, "end": <int>, "text": "<matched text>", "confidence": <0.0-1.0>, "implicit": <bool>}

Valid TYPE values: PERSON, ORGANIZATION, LOCATION, EMAIL, PHONE, SSN, CREDENTIAL

"implicit" should be true when the PII is inferred from context rather than explicitly stated (e.g. "the CEO of Tesla" implies Elon Musk).

If no PII is found, return an empty array: []

Return ONLY valid JSON. No other text."""

VALID_TYPES = {"PERSON", "ORGANIZATION", "LOCATION", "EMAIL", "PHONE", "SSN", "CREDENTIAL"}


@dataclass
class Span:
    pii_type: str
    start: int
    end: int
    text: str
    confidence: float
    implicit: bool = False


@dataclass
class Metrics:
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0

    @staticmethod
    def compute(tp: int, fp: int, fn: int) -> "Metrics":
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        return Metrics(precision=precision, recall=recall, f1=f1)


def spans_overlap(a_start, a_end, b_start, b_end):
    return a_start < b_end and b_start < a_end


def count_matches(expected: list[Span], detected: list[Span]) -> tuple[int, int, int]:
    """Greedy entity-level matching (mirrors eval.rs logic)."""
    matched_exp = [False] * len(expected)
    matched_det = [False] * len(detected)

    for di, det in enumerate(detected):
        for ei, exp in enumerate(expected):
            if matched_exp[ei]:
                continue
            if exp.pii_type.upper() not in VALID_TYPES:
                continue
            if (exp.pii_type.upper() == det.pii_type.upper()
                    and spans_overlap(exp.start, exp.end, det.start, det.end)):
                matched_exp[ei] = True
                matched_det[di] = True
                break

    tp = sum(matched_det)
    fp = sum(not m for m in matched_det)
    fn = sum(not m for m in matched_exp)
    return tp, fp, fn


def count_matches_by_implicit(expected, detected, implicit: bool):
    exp_f = [s for s in expected if s.implicit == implicit]
    det_f = [s for s in detected if s.implicit == implicit]
    return count_matches(exp_f, det_f)


def call_llama(prompt: str, model_path: Path = None, attempt: int = 1) -> str:
    """Call llama-server HTTP API and return raw output text."""
    import urllib.request
    model_id = os.environ.get("LMS_MODEL", "")
    body = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 4096,
        "seed": 42,
    }
    if model_id:
        body["model"] = model_id
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{SERVER_URL}/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read())
            msg = data["choices"][0]["message"]
            content = msg.get("content", "").strip()
            if not content:
                reasoning = msg.get("reasoning_content", "")
                if reasoning:
                    print(f"    [note: content empty, checking reasoning ({len(reasoning)} chars)]")
            # Extract token usage for latency reporting
            usage = data.get("usage", {})
            timings = data.get("timings", {})
            return content, usage, timings
    except Exception as e:
        print(f"  [attempt {attempt}] server error: {e}", file=sys.stderr)
        return "", {}, {}


def parse_response(raw: str) -> list[Span]:
    """Parse model JSON output into Span list. Strips markdown fences."""
    trimmed = raw.strip()
    if not trimmed:
        return []

    # Strip markdown code fences
    if trimmed.startswith("```"):
        trimmed = re.sub(r"^```(?:json)?\s*", "", trimmed)
        trimmed = re.sub(r"\s*```\s*$", "", trimmed)
        trimmed = trimmed.strip()

    # Try to extract JSON array if model added extra text
    match = re.search(r'\[.*\]', trimmed, re.DOTALL)
    if match:
        trimmed = match.group(0)

    try:
        raw_spans = json.loads(trimmed)
    except json.JSONDecodeError:
        return []

    if not isinstance(raw_spans, list):
        return []

    spans = []
    for s in raw_spans:
        if not isinstance(s, dict):
            continue
        ptype = str(s.get("type", "")).upper()
        if ptype not in VALID_TYPES:
            continue
        try:
            spans.append(Span(
                pii_type=ptype,
                start=int(s["start"]),
                end=int(s["end"]),
                text=str(s.get("text", "")),
                confidence=float(s.get("confidence", 0.0)),
                implicit=bool(s.get("implicit", False)),
            ))
        except (KeyError, ValueError, TypeError):
            continue
    return spans


def load_benchmark(path: Path) -> list[dict]:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def entry_to_spans(entry: dict) -> list[Span]:
    return [
        Span(
            pii_type=s["type"],
            start=s["start"],
            end=s["end"],
            text=s["text"],
            confidence=s["confidence"],
            implicit=s.get("implicit", False),
        )
        for s in entry.get("spans", [])
    ]


def main():
    # Check server is reachable
    import urllib.request
    # Health check: llama-server uses /health, LM Studio uses /v1/models
    try:
        with urllib.request.urlopen(f"{SERVER_URL}/v1/models", timeout=5) as resp:
            resp.read()
    except Exception:
        try:
            with urllib.request.urlopen(f"{SERVER_URL}/health", timeout=5) as resp:
                resp.read()
        except Exception as e:
            print(f"Cannot reach server at {SERVER_URL}: {e}")
            sys.exit(1)

    model_id = os.environ.get("LMS_MODEL", "auto")
    print(f"Model:     {model_id}")
    print(f"Benchmark: {BENCHMARK_PATH}")
    print()

    entries = load_benchmark(BENCHMARK_PATH)
    print(f"Loaded {len(entries)} benchmark entries")
    print("=" * 70)

    total_tp, total_fp, total_fn = 0, 0, 0
    explicit_tp, explicit_fp, explicit_fn = 0, 0, 0
    implicit_tp, implicit_fp, implicit_fn = 0, 0, 0
    entry_results = []

    latencies = []
    prompt_tps_list = []
    gen_tps_list = []

    for i, entry in enumerate(entries):
        prompt = entry["prompt"]
        expected = entry_to_spans(entry)
        excerpt = prompt[:57] + "..." if len(prompt) > 60 else prompt

        print(f"\n[{i}] {excerpt}")
        print(f"    Expected: {len(expected)} spans")

        t0 = time.time()
        raw_output, usage, timings = call_llama(prompt, MODEL_PATH)
        elapsed = time.time() - t0
        latencies.append(elapsed)

        # Token throughput from server timings
        prompt_tok = usage.get("prompt_tokens", 0)
        gen_tok = usage.get("completion_tokens", 0)
        prompt_tps = timings.get("prompt_per_second", 0)
        gen_tps = timings.get("predicted_per_second", 0)
        if prompt_tps:
            prompt_tps_list.append(prompt_tps)
        if gen_tps:
            gen_tps_list.append(gen_tps)

        # Retry once on parse failure
        detected = parse_response(raw_output)
        if not detected and expected and raw_output:
            print(f"    Parse failed, retrying...")
            raw_output, _, _ = call_llama(prompt, MODEL_PATH, attempt=2)
            detected = parse_response(raw_output)

        print(f"    Detected: {len(detected)} spans ({elapsed:.1f}s) [prompt={prompt_tok}tok gen={gen_tok}tok]")
        if gen_tps:
            print(f"    Throughput: prompt={prompt_tps:.1f} t/s  gen={gen_tps:.1f} t/s")
        for d in detected:
            print(f"      {d.pii_type}: \"{d.text}\" [{d.start}:{d.end}] conf={d.confidence} implicit={d.implicit}")

        tp, fp, fn = count_matches(expected, detected)
        total_tp += tp; total_fp += fp; total_fn += fn

        etp, efp, efn = count_matches_by_implicit(expected, detected, implicit=False)
        explicit_tp += etp; explicit_fp += efp; explicit_fn += efn

        itp, ifp, ifn = count_matches_by_implicit(expected, detected, implicit=True)
        implicit_tp += itp; implicit_fp += ifp; implicit_fn += ifn

        print(f"    TP={tp} FP={fp} FN={fn}")
        entry_results.append((excerpt, len(expected), len(detected), tp, fp, fn))

    # Compute final metrics
    overall = Metrics.compute(total_tp, total_fp, total_fn)
    explicit = Metrics.compute(explicit_tp, explicit_fp, explicit_fn)
    implicit_ = Metrics.compute(implicit_tp, implicit_fp, implicit_fn)

    print("\n" + "=" * 70)
    print(f"=== PII Eval Report: {model_id} ===")
    print(f"Entries evaluated: {len(entries)}")
    print()
    print(f"{'Category':<20} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("-" * 54)
    print(f"{'Overall':<20} {overall.precision:>10.3f} {overall.recall:>10.3f} {overall.f1:>10.3f}")
    print(f"{'Explicit PII':<20} {explicit.precision:>10.3f} {explicit.recall:>10.3f} {explicit.f1:>10.3f}")
    print(f"{'Implicit PII':<20} {implicit_.precision:>10.3f} {implicit_.recall:>10.3f} {implicit_.f1:>10.3f}")
    print()

    # Latency summary
    if latencies:
        avg_lat = sum(latencies) / len(latencies)
        min_lat = min(latencies)
        max_lat = max(latencies)
        p50 = sorted(latencies)[len(latencies) // 2]
        print(f"{'Latency (s)':<20} {'Avg':>10} {'P50':>10} {'Min':>10} {'Max':>10}")
        print("-" * 54)
        print(f"{'Wall-clock':<20} {avg_lat:>10.2f} {p50:>10.2f} {min_lat:>10.2f} {max_lat:>10.2f}")
    if prompt_tps_list:
        avg_ptps = sum(prompt_tps_list) / len(prompt_tps_list)
        print(f"\nAvg prompt throughput:  {avg_ptps:.1f} tok/s")
    if gen_tps_list:
        avg_gtps = sum(gen_tps_list) / len(gen_tps_list)
        print(f"Avg gen throughput:    {avg_gtps:.1f} tok/s")
    print()

    # Validate recall targets
    print("Recall Target Validation:")
    exp_pass = explicit.recall >= 0.90
    imp_pass = implicit_.recall >= 0.70
    print(f"  Explicit PII recall: {explicit.recall:.1%} (target >= 90%) {'PASS' if exp_pass else 'FAIL'}")
    print(f"  Implicit PII recall: {implicit_.recall:.1%} (target >= 70%) {'PASS' if imp_pass else 'FAIL'}")

    if explicit.recall < 0.60:
        print("  ** KILL CRITERION: Explicit recall < 60% **")
    if implicit_.recall < 0.60:
        print("  ** KILL CRITERION: Implicit recall < 60% **")

    print()
    print("Per-entry breakdown:")
    for i, (excerpt, exp_cnt, det_cnt, tp, fp, fn) in enumerate(entry_results):
        print(f"  [{i}] {excerpt} | expected={exp_cnt} detected={det_cnt} TP={tp} FP={fp} FN={fn}")

    # Exit code based on targets
    if exp_pass and imp_pass:
        print("\nAll recall targets met.")
        sys.exit(0)
    else:
        print("\nRecall targets NOT met.")
        sys.exit(1)


if __name__ == "__main__":
    main()
