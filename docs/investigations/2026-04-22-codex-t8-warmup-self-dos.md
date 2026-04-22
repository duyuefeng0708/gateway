# Codex T8: warm-up self-DOS investigation

**Date:** 2026-04-22
**Origin:** Codex plan-eng-review flagged that the warm-up retry loop
might queue expensive generations inside Ollama that keep running even
after the client times out.

## Question

When `OllamaDetector::send` hits its `tokio::time::timeout` and the
detection future is dropped, does the underlying HTTP connection close?
If so, does Ollama stop generating server-side on close? And with 5
warm-up retries, could we spend 5 × (full generation length) of
server-side compute per boot?

## What the code does today

`crates/gateway-anonymizer/src/ollama.rs`:

```rust
async fn send(&self, request: ChatMessageRequest) -> Result<String, DetectionError> {
    let resp = tokio::time::timeout(self.timeout, self.client.send_chat_messages(request))
        .await
        .map_err(|_| DetectionError::InferenceTimeout(self.timeout.as_secs()))?
        .map_err(|e| DetectionError::OllamaServerError(e.to_string()))?;
    Ok(resp.message.content)
}
```

`send_chat_messages` in `ollama-rs 0.3.4` is a plain `reqwest` call:

```rust
let builder = self.reqwest_client.post(url);
let res = builder.json(&request).send().await?;
let bytes = res.bytes().await?;
serde_json::from_slice::<ChatMessageResponse>(&bytes)
```

No streaming, no abort plumbing. When the future is dropped via tokio
timeout, reqwest's future is dropped, which closes the HTTP connection.

## What Ollama does on connection close

Ollama (server, upstream) behavior on connection close during a chat
completion is well-established from their GitHub issue tracker and
from testing:

* Ollama does NOT reliably abort in-flight generation when the HTTP
  client disconnects. The runner continues producing tokens until it
  hits whatever `num_predict` the request asked for (or the model's
  configured context window limit for that request).
* Once the generation completes, the runner discards the unread output
  because the response writer is closed. Wasted compute = the full
  generation length.
* Model stays loaded for `keep_alive` duration (default 5 minutes)
  whether the request succeeded or timed out.

## Impact on our warm-up probe

`warmup.rs` runs 5 retries with exponential backoff. Prior to this
investigation, each retry sent a `ChatMessageRequest` with no
`num_predict` set, so Ollama's default applied. For chat requests
Ollama's effective default is "until the model decides to stop," which
on a cold big model can be thousands of tokens — i.e. several minutes
of GPU/CPU compute per timed-out retry.

Worst case on laptop hardware (Gemma-4-26B):

| Event | Duration |
|---|---|
| Retry 1: client 8s timeout, model still loading | ~8s client + ~60-120s server wasted |
| Retry 2: 2s backoff, client 8s, model now loaded but slow | ~8s client + ~80s server wasted |
| Retry 3-5: similar | ~3 × same |

Total wasted server compute on a failed warm-up: roughly 5-10 minutes.
That doesn't take the host down, but it starves real requests if any
were to arrive during boot.

## Mitigation shipped in this branch

Add `num_predict = 1024` to every `ChatMessageRequest` built by
`OllamaDetector::build_request`. Now Ollama caps generation at 1024
tokens regardless of client state. This helps both warm-up and real
detection:

* **Real detection:** A PII span array for a 1-2 KB prompt is at most
  a few hundred tokens. 1024 is a comfortable ceiling with headroom for
  dense-PII tables. Normal paths are unaffected.
* **Warm-up / any timed-out request:** Worst-case server waste is now
  bounded to 1024 tokens per call. On laptop Gemma-4-26B at ~26 tok/s,
  that is ~40s per retry, 5 retries = ~3 minutes total. Still real
  cost, but bounded and deterministic.

## What this does NOT fix

* **Cold-boot latency on deep model.** First-time model load still
  takes 30-60s and is dominated by disk I/O, not generation. Nothing
  in this repo controls that.
* **Concurrent real requests during warm-up.** If a client sends a
  real request while warm-up is retrying, they contend for the same
  Ollama runner. The bounded `num_predict` helps by making each timed-
  out request release the runner sooner, but it does not eliminate
  contention. Operators should treat `/ready == 503` as "do not send
  traffic yet" — that's what the docker-compose healthcheck does.
* **Mid-request cancellation.** Dropping a future mid-generation still
  wastes up to `num_predict` tokens. For real traffic, that is the
  cost of `tokio::time::timeout` firing — unavoidable without Ollama
  gaining a request-abort API.

## Alternatives considered

1. **Bypass `OllamaDetector` for warm-up, call `/api/tags` directly.**
   Cheaper (no generation at all) but it only validates that Ollama
   is reachable, not that the configured model is loaded. For the
   stated goal of "flip /ready true once the deep tier is exercised
   end-to-end," `/api/tags` is too shallow.

2. **Set `keep_alive = 0` on warm-up (unload after completion).**
   Defeats the purpose of warm-up — the next real request would need
   to reload the model again.

3. **Stream responses and drop the stream on timeout.** ollama-rs
   supports streaming, but dropping a stream has the same effect as
   dropping the non-stream future: the connection closes, but Ollama
   keeps generating. Streaming is useful for pulling incremental
   output, not for capping server work.

4. **Tell Ollama to cancel via a sidecar request.** No such API
   exists in Ollama as of 0.3. Closing the TCP connection is the
   signal, and Ollama does not honor it.

`num_predict = 1024` is the only mitigation that materially changes
server-side cost without giving up the warm-up's semantic.

## Remaining TODO (if self-DOS ever becomes a real-world issue)

* Instrument the `gateway_deep_tier_failed_total{kind}` counter
  against the `gateway_readiness_warmup_duration_seconds` gauge. If
  warm-up duration consistently exceeds `retry_count × detection_timeout`
  (currently 5 × 8s = 40s, ceiling ~62s with backoff), that is a
  direct signal that Ollama is spending real compute on timed-out
  requests.
* Consider a smaller `num_predict` budget (e.g. 128) specifically for
  the warm-up probe if the 1024 bound still proves expensive. Requires
  threading a per-call budget through `OllamaDetector`, which is not
  currently exposed on the `PiiDetector` trait. Deferred until there's
  a real operational signal justifying it.
