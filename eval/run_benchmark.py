#!/usr/bin/env python3
"""PII detection benchmark runner. Supports Ollama and llama.cpp/LM Studio backends.

Mirrors the entity-level matching logic from gateway's eval.rs:
  - Overlap-based matching (partial overlap counts)
  - Same PII type required
  - Greedy one-to-one matching
  - Separate metrics for explicit vs implicit PII

Recall targets (from Phase 1 plan):
  - Explicit PII recall >= 90%
  - Implicit PII recall >= 70%

Usage:
  # Ollama backend (default now that the gateway config ships with Ollama tags)
  python3 run_benchmark.py --backend ollama --model gemma4:e4b
  python3 run_benchmark.py --backend ollama --model gemma4:26b --dataset pii_100.jsonl

  # Legacy llama.cpp / LM Studio backend for comparison runs
  python3 run_benchmark.py --backend llamacpp
  LMS_MODEL=Gemma-4-26B-A4B python3 run_benchmark.py --backend llamacpp
"""

import argparse
import json
import os
import sys
import re
import time
from dataclasses import dataclass
from pathlib import Path

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


def count_matches(expected: list, detected: list) -> tuple:
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


# ---------------------------------------------------------------------------
# Backend: llama.cpp / LM Studio (OpenAI-compat)
# ---------------------------------------------------------------------------

def call_llamacpp(prompt: str, server_url: str, model_id: str = "") -> tuple:
    """Hit LM Studio / llama-server /v1/chat/completions. Returns (content, usage, timings)."""
    import urllib.request
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
        f"{server_url}/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read())
            msg = data["choices"][0]["message"]
            content = msg.get("content", "").strip()
            usage = data.get("usage", {})
            timings = data.get("timings", {})
            return content, usage, timings
    except Exception as e:
        print(f"  llamacpp error: {e}", file=sys.stderr)
        return "", {}, {}


# ---------------------------------------------------------------------------
# Backend: Ollama
# ---------------------------------------------------------------------------

def call_ollama(prompt: str, server_url: str, model: str) -> tuple:
    """Hit Ollama /api/chat with stream=false. Returns (content, usage, timings).

    Ollama reports timings in nanoseconds; we convert to the same shape the
    llama.cpp backend produces so the summary code stays uniform.
    """
    import urllib.request
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {
            "temperature": 0,
            "seed": 42,
            "num_predict": 4096,
        },
    }
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{server_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        # Ollama deep-model runs can take 90s+ on CPU; allow headroom.
        with urllib.request.urlopen(req, timeout=600) as resp:
            data = json.loads(resp.read())
            content = data.get("message", {}).get("content", "").strip()

            prompt_tok = data.get("prompt_eval_count", 0)
            gen_tok = data.get("eval_count", 0)
            prompt_ns = data.get("prompt_eval_duration", 0) or 0
            gen_ns = data.get("eval_duration", 0) or 0

            usage = {"prompt_tokens": prompt_tok, "completion_tokens": gen_tok}
            timings = {
                "prompt_per_second": (prompt_tok / (prompt_ns / 1e9)) if prompt_ns else 0,
                "predicted_per_second": (gen_tok / (gen_ns / 1e9)) if gen_ns else 0,
            }
            return content, usage, timings
    except Exception as e:
        print(f"  ollama error: {e}", file=sys.stderr)
        return "", {}, {}


def ollama_health(server_url: str) -> bool:
    """Return True if Ollama /api/tags responds."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{server_url}/api/tags", timeout=5) as resp:
            resp.read()
        return True
    except Exception:
        return False


def llamacpp_health(server_url: str) -> bool:
    """Return True if llama-server /v1/models or /health responds."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{server_url}/v1/models", timeout=5) as resp:
            resp.read()
        return True
    except Exception:
        pass
    try:
        with urllib.request.urlopen(f"{server_url}/health", timeout=5) as resp:
            resp.read()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def parse_response(raw: str) -> list:
    """Parse model JSON output into Span list. Strips markdown fences."""
    trimmed = raw.strip()
    if not trimmed:
        return []

    if trimmed.startswith("```"):
        trimmed = re.sub(r"^```(?:json)?\s*", "", trimmed)
        trimmed = re.sub(r"\s*```\s*$", "", trimmed)
        trimmed = trimmed.strip()

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


def load_benchmark(path: Path) -> list:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def entry_to_spans(entry: dict) -> list:
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--backend",
        choices=["ollama", "llamacpp"],
        default="ollama",
        help="Backend to hit. Default: ollama (matches shipped config defaults).",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("BENCHMARK_MODEL", "gemma4:e4b"),
        help="Model tag/name. For Ollama: e.g. gemma4:e4b, gemma4:26b. "
             "For llamacpp: reads LMS_MODEL env if this is unset.",
    )
    parser.add_argument(
        "--server",
        default=None,
        help="Server URL. Defaults: ollama=http://localhost:11434, "
             "llamacpp=http://127.0.0.1:8787",
    )
    parser.add_argument(
        "--dataset",
        default=str(Path(__file__).parent / "sample_benchmark.jsonl"),
        help="Path to JSONL benchmark dataset.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="If >0, evaluate only the first N entries. Useful for smoke tests.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="If set, write per-entry detection results as JSONL to this path.",
    )
    args = parser.parse_args()

    if args.server is None:
        args.server = (
            "http://localhost:11434" if args.backend == "ollama" else "http://127.0.0.1:8787"
        )

    # Health check
    if args.backend == "ollama":
        if not ollama_health(args.server):
            print(f"Cannot reach Ollama at {args.server}")
            print("Try: ollama serve   (and ollama pull", args.model + ")")
            sys.exit(1)
        model_id = args.model
        call_fn = lambda p: call_ollama(p, args.server, args.model)
    else:
        if not llamacpp_health(args.server):
            print(f"Cannot reach llama.cpp/LM Studio at {args.server}")
            sys.exit(1)
        model_id = os.environ.get("LMS_MODEL", args.model or "auto")
        call_fn = lambda p: call_llamacpp(p, args.server, model_id)

    print(f"Backend:   {args.backend}")
    print(f"Server:    {args.server}")
    print(f"Model:     {model_id}")
    print(f"Dataset:   {args.dataset}")

    entries = load_benchmark(Path(args.dataset))
    if args.limit and args.limit > 0:
        entries = entries[: args.limit]
    print(f"Loaded {len(entries)} benchmark entries")
    print("=" * 70)

    total_tp, total_fp, total_fn = 0, 0, 0
    explicit_tp, explicit_fp, explicit_fn = 0, 0, 0
    implicit_tp, implicit_fp, implicit_fn = 0, 0, 0
    entry_results = []
    output_records = []

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
        raw_output, usage, timings = call_fn(prompt)
        elapsed = time.time() - t0
        latencies.append(elapsed)

        prompt_tok = usage.get("prompt_tokens", 0)
        gen_tok = usage.get("completion_tokens", 0)
        prompt_tps = timings.get("prompt_per_second", 0)
        gen_tps = timings.get("predicted_per_second", 0)
        if prompt_tps:
            prompt_tps_list.append(prompt_tps)
        if gen_tps:
            gen_tps_list.append(gen_tps)

        detected = parse_response(raw_output)
        if not detected and expected and raw_output:
            print("    Parse failed, retrying...")
            raw_output, _, _ = call_fn(prompt)
            detected = parse_response(raw_output)

        print(f"    Detected: {len(detected)} spans ({elapsed:.1f}s) [prompt={prompt_tok}tok gen={gen_tok}tok]")
        if gen_tps:
            print(f"    Throughput: prompt={prompt_tps:.1f} t/s  gen={gen_tps:.1f} t/s")
        for d in detected:
            print(f"      {d.pii_type}: \"{d.text}\" [{d.start}:{d.end}] conf={d.confidence} implicit={d.implicit}")

        tp, fp, fn = count_matches(expected, detected)
        total_tp += tp
        total_fp += fp
        total_fn += fn

        etp, efp, efn = count_matches_by_implicit(expected, detected, implicit=False)
        explicit_tp += etp
        explicit_fp += efp
        explicit_fn += efn

        itp, ifp, ifn = count_matches_by_implicit(expected, detected, implicit=True)
        implicit_tp += itp
        implicit_fp += ifp
        implicit_fn += ifn

        print(f"    TP={tp} FP={fp} FN={fn}")
        entry_results.append((excerpt, len(expected), len(detected), tp, fp, fn))
        if args.output:
            output_records.append({
                "idx": i,
                "prompt": prompt,
                "expected": [s.__dict__ for s in expected],
                "detected": [s.__dict__ for s in detected],
                "tp": tp, "fp": fp, "fn": fn,
                "latency_s": elapsed,
            })

    overall = Metrics.compute(total_tp, total_fp, total_fn)
    explicit = Metrics.compute(explicit_tp, explicit_fp, explicit_fn)
    implicit_ = Metrics.compute(implicit_tp, implicit_fp, implicit_fn)

    print("\n" + "=" * 70)
    print(f"=== PII Eval Report: {model_id} ({args.backend}) ===")
    print(f"Entries evaluated: {len(entries)}")
    print()
    print(f"{'Category':<20} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("-" * 54)
    print(f"{'Overall':<20} {overall.precision:>10.3f} {overall.recall:>10.3f} {overall.f1:>10.3f}")
    print(f"{'Explicit PII':<20} {explicit.precision:>10.3f} {explicit.recall:>10.3f} {explicit.f1:>10.3f}")
    print(f"{'Implicit PII':<20} {implicit_.precision:>10.3f} {implicit_.recall:>10.3f} {implicit_.f1:>10.3f}")
    print()

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

    print("Recall Target Validation:")
    exp_pass = explicit.recall >= 0.90
    imp_pass = implicit_.recall >= 0.70
    print(f"  Explicit PII recall: {explicit.recall:.1%} (target >= 90%) {'PASS' if exp_pass else 'FAIL'}")
    print(f"  Implicit PII recall: {implicit_.recall:.1%} (target >= 70%) {'PASS' if imp_pass else 'FAIL'}")

    if explicit.recall < 0.60:
        print("  ** KILL CRITERION: Explicit recall < 60% **")
    if implicit_.recall < 0.60:
        print("  ** KILL CRITERION: Implicit recall < 60% **")

    if args.output:
        with open(args.output, "w") as f:
            for rec in output_records:
                f.write(json.dumps(rec) + "\n")
        print(f"\nPer-entry JSONL written to {args.output}")

    if exp_pass and imp_pass:
        print("\nAll recall targets met.")
        sys.exit(0)
    else:
        print("\nRecall targets NOT met.")
        sys.exit(1)


if __name__ == "__main__":
    main()
