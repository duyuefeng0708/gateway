#!/usr/bin/env python3
"""Generate a 100-entry PII benchmark dataset from declarative span specs.

Output: eval/pii_100.jsonl — one entry per line, each with:
  - prompt: the text the model sees
  - spans: list of ground-truth PII with byte offsets auto-computed

Categories (roughly):
  - Explicit PII: 35 entries (emails, SSNs, phones, names, credit cards, API keys, addresses)
  - Implicit PII: 25 entries (titular references like "the CEO of X")
  - Multi-PII: 20 entries (combinations of types in one prompt)
  - Non-PII control: 10 entries (no PII — test for false positives)
  - Code blocks: 10 entries (PII inside code blocks, verifies code-block handling)
  - Edge cases: 5 entries (Unicode names, international phones, punctuation)

Why declarative: hand-computing byte offsets for 100+ prompts is tedious and
error-prone. Declaring (prompt_template, [(type, text, implicit?), ...]) and
letting the script find offsets is correct by construction — offsets match
the exact substring we intend.

Limitation: span text must be unique within a prompt, otherwise offset
lookup picks the first occurrence. This is fine for all current entries;
verify with `python3 generate_pii_100.py --verify`.
"""

import argparse
import json
from pathlib import Path

# Entry format: (prompt, [(type, text, implicit_bool), ...])
# implicit=False is the default when omitted in a 2-tuple.
Entries = []


def add(prompt: str, spans):
    normalized = []
    for s in spans:
        if len(s) == 2:
            normalized.append((s[0], s[1], False))
        else:
            normalized.append(s)
    Entries.append((prompt, normalized))


# ---------------------------------------------------------------------------
# Explicit PII — emails, SSNs, phones, names, credit cards, API keys
# ---------------------------------------------------------------------------

add("Please email alice@example.com about the meeting.",
    [("EMAIL", "alice@example.com")])
add("Contact me at bob.jones@work.org for the quote.",
    [("EMAIL", "bob.jones@work.org")])
add("Send the report to priya.rao@mit.edu by Friday.",
    [("EMAIL", "priya.rao@mit.edu"), ("PERSON", "priya.rao")])
add("Forward this to help+support@company.co.uk please.",
    [("EMAIL", "help+support@company.co.uk")])
add("My name is John Smith and my SSN is 123-45-6789.",
    [("PERSON", "John Smith"), ("SSN", "123-45-6789")])
add("Patient SSN 987-65-4321 has an appointment tomorrow.",
    [("SSN", "987-65-4321")])
add("Call me at (555) 867-5309 or reach me at bob.jones@work.org.",
    [("PHONE", "(555) 867-5309"), ("EMAIL", "bob.jones@work.org")])
add("Phone: 415-555-0199, available after 3pm PT.",
    [("PHONE", "415-555-0199")])
add("International contact: +44 20 7946 0958 (London office).",
    [("PHONE", "+44 20 7946 0958"), ("LOCATION", "London")])
add("Her mobile is +1 (212) 555-0147, text only.",
    [("PHONE", "+1 (212) 555-0147")])
add("My name is Sarah Kim and I live in Seattle.",
    [("PERSON", "Sarah Kim"), ("LOCATION", "Seattle")])
add("Dr. Ahmed El-Khoury will chair the session.",
    [("PERSON", "Dr. Ahmed El-Khoury")])
add("The API key sk_FAKE_not_a_real_live_key is in the vault.",
    [("CREDENTIAL", "sk_FAKE_not_a_real_live_key")])
add("Use Authorization: Bearer bearer-FAKE-not-a-real-token-123 to authenticate.",
    [("CREDENTIAL", "bearer-FAKE-not-a-real-token-123")])
add("The OpenAI key sk-FAKE-proj-abc123def456 must never appear in logs.",
    [("CREDENTIAL", "sk-FAKE-proj-abc123def456")])
add("My credit card number is 4000-0000-0000-0002, exp 08/28.",
    [("CREDENTIAL", "4000-0000-0000-0002")])
add("Password for the admin panel is ShipItNow!2026.",
    [("CREDENTIAL", "ShipItNow!2026")])
add("AWS access key AKIAIOSFODNN7EXAMPLE is rotated quarterly.",
    [("CREDENTIAL", "AKIAIOSFODNN7EXAMPLE")])
add("Ship to 1600 Pennsylvania Avenue NW, Washington, DC 20500.",
    [("LOCATION", "1600 Pennsylvania Avenue NW, Washington, DC 20500")])
add("The invoice goes to 221B Baker Street, London NW1 6XE.",
    [("LOCATION", "221B Baker Street, London NW1 6XE")])
add("Alice Liang's direct line is 206-555-0142.",
    [("PERSON", "Alice Liang"), ("PHONE", "206-555-0142")])
add("Acme Corp signed the contract on Tuesday.",
    [("ORGANIZATION", "Acme Corp")])
add("Nvidia's stock closed up 3% yesterday.",
    [("ORGANIZATION", "Nvidia")])
add("The meeting is at Google Mountain View HQ.",
    [("ORGANIZATION", "Google"), ("LOCATION", "Mountain View")])
add("Can you introduce me to someone at OpenAI?",
    [("ORGANIZATION", "OpenAI")])
add("Jane Doe from Tesla will present on battery chemistry.",
    [("PERSON", "Jane Doe"), ("ORGANIZATION", "Tesla")])
add("Ship to Amazon DSP1, Mountain Avenue, Sunnyvale.",
    [("ORGANIZATION", "Amazon"), ("LOCATION", "Mountain Avenue, Sunnyvale")])
add("The GitHub token ghp_FAKEFAKEFAKE1234567890abcd has write access.",
    [("CREDENTIAL", "ghp_FAKEFAKEFAKE1234567890abcd")])
add("Stripe secret sk_FAKE_not_a_real_test_key expired.",
    [("CREDENTIAL", "sk_FAKE_not_a_real_test_key")])
add("Postal code 94107 is in San Francisco.",
    [("LOCATION", "San Francisco")])
add("Flight tomorrow: SFO to LAX at 8:15 AM.",
    [("LOCATION", "SFO"), ("LOCATION", "LAX")])
add("My dentist is Dr. Nguyen on Oak Street.",
    [("PERSON", "Dr. Nguyen"), ("LOCATION", "Oak Street")])
add("Marcus Rodriguez will handle the Q3 audit.",
    [("PERSON", "Marcus Rodriguez")])
add("Call Jennifer Park at x4821 when you arrive.",
    [("PERSON", "Jennifer Park"), ("PHONE", "x4821")])
add("Emma Thompson (emma@kew.org) leads the gardens team.",
    [("PERSON", "Emma Thompson"), ("EMAIL", "emma@kew.org"), ("ORGANIZATION", "kew.org")])

# ---------------------------------------------------------------------------
# Implicit PII — inferred identities, requires reasoning to detect
# ---------------------------------------------------------------------------

add("The CEO of Tesla disclosed the quarterly earnings.",
    [("ORGANIZATION", "Tesla"),
     ("PERSON", "The CEO of Tesla", True)])
add("The president of Apple spoke at the town hall.",
    [("ORGANIZATION", "Apple"),
     ("PERSON", "The president of Apple", True)])
add("My therapist suggested a different approach.",
    [("PERSON", "My therapist", True)])
add("The CFO of the company I work for was fired.",
    [("PERSON", "The CFO of the company I work for", True)])
add("The founder of SpaceX tweeted about the launch.",
    [("ORGANIZATION", "SpaceX"),
     ("PERSON", "The founder of SpaceX", True)])
add("Our head of HR has been on vacation for two weeks.",
    [("PERSON", "Our head of HR", True)])
add("The COO of Anthropic was at the summit.",
    [("ORGANIZATION", "Anthropic"),
     ("PERSON", "The COO of Anthropic", True)])
add("The lead attorney on the case resigned this morning.",
    [("PERSON", "The lead attorney on the case", True)])
add("The CEO of the company that acquired us yesterday called.",
    [("PERSON", "The CEO of the company that acquired us yesterday", True)])
add("My doctor warned me about the side effects.",
    [("PERSON", "My doctor", True)])
add("The principal at my kid's school emailed the parents.",
    [("PERSON", "The principal at my kid's school", True)])
add("Our chief data officer rejected the proposal.",
    [("PERSON", "Our chief data officer", True)])
add("The Google Brain team lead left last month.",
    [("ORGANIZATION", "Google"),
     ("PERSON", "The Google Brain team lead", True)])
add("The chairman of the Federal Reserve hinted at rate cuts.",
    [("ORGANIZATION", "the Federal Reserve"),
     ("PERSON", "The chairman of the Federal Reserve", True)])
add("The prime minister of the UK visited the troops.",
    [("LOCATION", "the UK"),
     ("PERSON", "The prime minister of the UK", True)])
add("The head nurse on the third floor knows my case.",
    [("PERSON", "The head nurse on the third floor", True)])
add("My landlord in Brooklyn raised the rent again.",
    [("LOCATION", "Brooklyn"),
     ("PERSON", "My landlord in Brooklyn", True)])
add("The HR business partner for our team is on maternity leave.",
    [("PERSON", "The HR business partner for our team", True)])
add("The developer who pushed that commit should own the fix.",
    [("PERSON", "The developer who pushed that commit", True)])
add("My accountant at the Palo Alto office is reviewing it.",
    [("LOCATION", "Palo Alto"),
     ("PERSON", "My accountant at the Palo Alto office", True)])
add("The son of the founder is joining as an intern.",
    [("PERSON", "The son of the founder", True)])
add("The author of the bestselling biography will do a signing.",
    [("PERSON", "The author of the bestselling biography", True)])
add("Our family friend from Seattle passed away.",
    [("LOCATION", "Seattle"),
     ("PERSON", "Our family friend from Seattle", True)])
add("The general counsel at Meta reviewed the filing.",
    [("ORGANIZATION", "Meta"),
     ("PERSON", "The general counsel at Meta", True)])
add("My roommate from freshman year is visiting.",
    [("PERSON", "My roommate from freshman year", True)])

# ---------------------------------------------------------------------------
# Multi-PII — multiple types in one prompt
# ---------------------------------------------------------------------------

add("Patient Sarah Chen (DOB 1987-03-15, SSN 555-44-3333) will arrive at 3pm.",
    [("PERSON", "Sarah Chen"), ("SSN", "555-44-3333")])
add("Fred at fred@xyz.com has an order shipping to 1 Main St, Boston, MA.",
    [("PERSON", "Fred"), ("EMAIL", "fred@xyz.com"),
     ("LOCATION", "1 Main St, Boston, MA")])
add("Ship the NDAs to Daniel Park, dan@park.co, or call 415-555-2020.",
    [("PERSON", "Daniel Park"), ("EMAIL", "dan@park.co"), ("PHONE", "415-555-2020")])
add("Michael Torres (mike@torres.dev) flagged the bug; his phone is 650-555-0099.",
    [("PERSON", "Michael Torres"), ("EMAIL", "mike@torres.dev"),
     ("PHONE", "650-555-0099")])
add("Alice and Bob both work at Microsoft in Redmond.",
    [("PERSON", "Alice"), ("PERSON", "Bob"),
     ("ORGANIZATION", "Microsoft"), ("LOCATION", "Redmond")])
add("Call Priya at priya@lab.ai, backup phone 617-555-3901.",
    [("PERSON", "Priya"), ("EMAIL", "priya@lab.ai"), ("PHONE", "617-555-3901")])
add("The contract between Acme Inc and Beta LLC was signed by Tim Cook.",
    [("ORGANIZATION", "Acme Inc"), ("ORGANIZATION", "Beta LLC"),
     ("PERSON", "Tim Cook")])
add("Satya Nadella, CEO of Microsoft, confirmed the acquisition of Activision.",
    [("PERSON", "Satya Nadella"), ("ORGANIZATION", "Microsoft"),
     ("ORGANIZATION", "Activision")])
add("Meet Wei Zhang at 2pm at Stanford, room 104. Her email is wz@stanford.edu.",
    [("PERSON", "Wei Zhang"), ("LOCATION", "Stanford"),
     ("EMAIL", "wz@stanford.edu")])
add("Forward the contract to legal@anthropic.com and cc Dario Amodei.",
    [("EMAIL", "legal@anthropic.com"), ("ORGANIZATION", "anthropic.com"),
     ("PERSON", "Dario Amodei")])
add("Customer ID 4000-0000-0000-0069 belongs to Emily Stone, emily@stone.io.",
    [("CREDENTIAL", "4000-0000-0000-0069"),
     ("PERSON", "Emily Stone"),
     ("EMAIL", "emily@stone.io")])
add("Our new hire Akira Tanaka (akira.tanaka@company.jp) starts Monday in Tokyo.",
    [("PERSON", "Akira Tanaka"),
     ("EMAIL", "akira.tanaka@company.jp"),
     ("LOCATION", "Tokyo")])
add("The board includes Jensen Huang from Nvidia and Lisa Su from AMD.",
    [("PERSON", "Jensen Huang"), ("ORGANIZATION", "Nvidia"),
     ("PERSON", "Lisa Su"), ("ORGANIZATION", "AMD")])
add("Dr. Nguyen at UCSF has my records; reach him at 415-476-1000.",
    [("PERSON", "Dr. Nguyen"), ("ORGANIZATION", "UCSF"),
     ("PHONE", "415-476-1000")])
add("Jennifer, the CTO of Stripe, will demo at 2pm from Dublin.",
    [("PERSON", "Jennifer"), ("ORGANIZATION", "Stripe"),
     ("LOCATION", "Dublin"),
     ("PERSON", "the CTO of Stripe", True)])
add("Contact us at +1-800-555-TECH or support@tech-corp.io.",
    [("PHONE", "+1-800-555-TECH"),
     ("EMAIL", "support@tech-corp.io")])
add("Ahmed bin Rashid, director of operations, is flying in from Dubai tomorrow.",
    [("PERSON", "Ahmed bin Rashid"), ("LOCATION", "Dubai")])
add("CEO Lisa Patel (lpatel@startup.ai, 408-555-9876) owns the decision.",
    [("PERSON", "Lisa Patel"), ("EMAIL", "lpatel@startup.ai"),
     ("PHONE", "408-555-9876")])
add("Ship to: Rohan Iyer, 42 Wallaby Way, Sydney NSW 2000, Australia.",
    [("PERSON", "Rohan Iyer"),
     ("LOCATION", "42 Wallaby Way, Sydney NSW 2000, Australia")])
add("The Google DeepMind team (Demis Hassabis, CEO) published a new paper.",
    [("ORGANIZATION", "Google DeepMind"), ("PERSON", "Demis Hassabis")])

# ---------------------------------------------------------------------------
# Non-PII control — should produce no spans, verifies false-positive rate
# ---------------------------------------------------------------------------

add("The weather in Paris will be sunny this weekend.", [])
add("Can you help me refactor this TypeScript function?", [])
add("Explain the difference between TCP and UDP.", [])
add("What are the main causes of the French Revolution?", [])
add("How do I center a div in CSS?", [])
add("Summarize the three laws of thermodynamics.", [])
add("Generate a list of ten potential product names.", [])
add("Translate 'hello world' into Mandarin, Japanese, and Korean.", [])
add("Write a haiku about autumn.", [])
add("What is the integral of x squared?", [])

# ---------------------------------------------------------------------------
# Code blocks — PII inside code blocks (proxy should extract + restore)
# ---------------------------------------------------------------------------

add("```python\nemail = 'alice@example.com'\n```\nCan you review this?",
    [("EMAIL", "alice@example.com")])
add("Here's the config:\n```yaml\napi_key: sk_FAKE_abc123def456_live\n```",
    [("CREDENTIAL", "sk_FAKE_abc123def456_live")])
add("```sql\nSELECT * FROM users WHERE email = 'bob@company.com';\n```\nIs this safe?",
    [("EMAIL", "bob@company.com")])
add("Bug report: my name is Karen Wells but the app shows 'Kerry Wells'.",
    [("PERSON", "Karen Wells"), ("PERSON", "Kerry Wells")])
add("```json\n{\"phone\": \"415-555-0100\", \"name\": \"Alex\"}\n```",
    [("PHONE", "415-555-0100"), ("PERSON", "Alex")])
add("The function returns {\"user\": \"mia@dev.io\"}. Is that OK?",
    [("EMAIL", "mia@dev.io")])
add("Test fixture:\n```\nuser: John Wu\nemail: jwu@test.com\n```",
    [("PERSON", "John Wu"), ("EMAIL", "jwu@test.com")])
add("```bash\nexport AWS_KEY=AKIAI44QH8DHBEXAMPLE\n```\nRotate this please.",
    [("CREDENTIAL", "AKIAI44QH8DHBEXAMPLE")])
add("My test script pings api@internal.co with SSN 123-45-0000 in the body.",
    [("EMAIL", "api@internal.co"), ("SSN", "123-45-0000")])
add("```typescript\nconst user = { phone: '+1-650-555-0100', city: 'Palo Alto' };\n```",
    [("PHONE", "+1-650-555-0100"), ("LOCATION", "Palo Alto")])

# ---------------------------------------------------------------------------
# Edge cases — Unicode, international, punctuation
# ---------------------------------------------------------------------------

add("Rendez-vous avec Renée Lévêque demain à Montréal.",
    [("PERSON", "Renée Lévêque"), ("LOCATION", "Montréal")])
add("我们的顾问是张伟博士 (zhang.wei@cn.co).",
    [("PERSON", "张伟博士"), ("EMAIL", "zhang.wei@cn.co")])
add("Call from +81-3-1234-5678 (Japan office) at 9am JST.",
    [("PHONE", "+81-3-1234-5678"), ("LOCATION", "Japan")])
add("Write to Björn Ørsted at bjorn@nordic.dk or at Östermalmsgatan 12, Stockholm.",
    [("PERSON", "Björn Ørsted"), ("EMAIL", "bjorn@nordic.dk"),
     ("LOCATION", "Östermalmsgatan 12, Stockholm")])
add("Send the package to D'Angelo O'Brien at 555 O'Malley Ave.",
    [("PERSON", "D'Angelo O'Brien"), ("LOCATION", "555 O'Malley Ave")])


# ---------------------------------------------------------------------------
# Emit JSONL
# ---------------------------------------------------------------------------

def locate(prompt: str, text: str) -> tuple:
    """Find first byte-offset occurrence of text in prompt. Returns (start, end)."""
    idx = prompt.find(text)
    if idx < 0:
        raise ValueError(f"span text {text!r} not found in prompt {prompt!r}")
    return idx, idx + len(text)


def build_entry(prompt: str, span_specs: list) -> dict:
    """Compute byte offsets for each (type, text) spec.

    Overlapping spans are allowed (and expected) — an implicit span like
    "The CEO of Tesla" genuinely contains the explicit ORG span "Tesla",
    and both should be ground-truth for the benchmark. The real detector's
    merge_spans keeps the longest when types overlap in its output, but
    the benchmark's count_matches is type-scoped so both entries can score.

    Duplicate literal text is disambiguated by occurrence index: if the
    prompt contains "Alice" twice and the specs list "Alice" twice, the
    first spec finds the first occurrence and the second spec finds the
    second occurrence.
    """
    spans = []
    # For duplicate span-text disambiguation: track the (start, end) of
    # every previously claimed (type, text, start, end). A new spec with
    # the SAME text must land at a later position than all previous claims
    # of that text.
    occurrences_used_for_text = {}

    for (ptype, text, implicit) in span_specs:
        search_from = occurrences_used_for_text.get(text, 0)
        idx = prompt.find(text, search_from)
        if idx < 0:
            raise ValueError(
                f"span text {text!r} not findable in {prompt!r} "
                f"past offset {search_from}"
            )
        end = idx + len(text)
        occurrences_used_for_text[text] = end
        spans.append({
            "type": ptype,
            "start": idx,
            "end": end,
            "text": text,
            "confidence": 1.0,
            "implicit": implicit,
        })
    return {"prompt": prompt, "spans": spans}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=str(Path(__file__).parent / "pii_100.jsonl"),
        help="Output path for the generated JSONL.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Only verify that every span text is findable; do not write output.",
    )
    args = parser.parse_args()

    built = []
    failures = 0
    for prompt, specs in Entries:
        try:
            built.append(build_entry(prompt, specs))
        except ValueError as e:
            print(f"VERIFY FAIL: {e}")
            failures += 1

    total_spans = sum(len(e["spans"]) for e in built)
    explicit = sum(1 for e in built for s in e["spans"] if not s["implicit"])
    implicit = total_spans - explicit

    print(f"Entries:        {len(built)}")
    print(f"Total spans:    {total_spans}")
    print(f"Explicit spans: {explicit}")
    print(f"Implicit spans: {implicit}")
    print(f"Failures:       {failures}")

    if args.verify:
        if failures:
            raise SystemExit(1)
        print("All span texts verified against prompts.")
        return

    if failures:
        print("Refusing to write output with verification failures.", file=__import__("sys").stderr)
        raise SystemExit(1)

    with open(args.output, "w") as f:
        for e in built:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
