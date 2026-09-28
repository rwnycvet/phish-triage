# phish-triage

A phishing email triage tool. Deterministic header and IOC extraction in Python, with an LLM analyst layer via Groq producing a structured verdict.

## The problem

Tier-1 SOC analysts spend a large share of their day on user-reported emails. Each one needs the same work: read the headers, check whether the sender authenticated, pull out the links and addresses, and decide whether it is a phish, a false alarm, or something that needs escalation.

The headers are mechanical. The decision is judgment. This tool splits those apart deliberately.

## Architecture

Two layers, doing different kinds of work:

| Layer | Module | Job | Property |
| --- | --- | --- | --- |
| Parser | `src/phish_triage/parser.py` | Extract facts from the raw email | Deterministic — identical input always produces identical output |
| Analyst | `src/phish_triage/analyst.py` | Weigh those facts into a verdict | Probabilistic — an LLM reasoning over the extracted facts |

The parser uses Python's standard-library `email` module. It pulls the `From` display name and address separately, `Reply-To`, `Return-Path`, the `Subject`, and the `Authentication-Results` header (normalized to a single line), then regexes URLs, hostnames and IPv4 addresses out of the message body as indicators of compromise.

The analyst receives that fact dictionary as JSON — **never the raw email** — and returns a fixed schema: verdict, severity, confidence, key indicators, a required benign explanation, reasoning, and a recommended action.

### Why the split

A security tool must not invent its evidence. The parser cannot report a sender address that was not in the email, because it has no capacity to generate anything. An LLM can. So every verifiable fact is extracted in code, and the model is asked only for the part that genuinely requires judgment.

Handing the model a structured fact sheet rather than raw text also reduces the prompt-injection surface. Attacker-controlled body text does not reach the model directly, and the system prompt instructs the model to treat all supplied values as data rather than instructions.

## Usage

```
uv sync
```

Create a `.env` file in the project root:

```
GROQ_API_KEY=your_key_here
```

Then:

```
uv run python -m phish_triage.analyst samples/suspicious_01.eml
```

Exit codes: `0` success, `1` runtime failure, `2` bad usage. Errors go to stderr, so stdout stays pure JSON and can be piped.

## Example output

```json
{
  "verdict": "phishing",
  "severity": "high",
  "confidence": 0.92,
  "key_indicators": [
    "lookalike sender domain (acmeb4nk-verify.example.net)",
    "reply-to uses free webmail provider",
    "DMARC fail",
    "SPF fail",
    "bare IP address link (http://198.51.100.47)"
  ],
  "benign_explanation": "none",
  "reasoning": "The email uses a look-alike domain, a free-webmail reply-to address, and contains links to a bare IP and a typosquatted domain...",
  "recommended_action": "Quarantine the message, block the URLs, and launch a phishing incident response investigation."
}
```

## Test samples

Three fixtures in `samples/`, all using RFC 2606 reserved domains and RFC 5737 reserved IP ranges so that no fixture contains a live domain or a usable phishing template:

| File | What it is | Expected verdict |
| --- | --- | --- |
| `suspicious_01.eml` | Credential phish — lookalike domain, all auth fails, bare-IP link | phishing |
| `legitimate_01.eml` | Routine invoice notice, SPF/DKIM/DMARC all pass and align | legitimate |
| `ambiguous_01.eml` | Legitimate sender via a third-party ESP with broken DKIM | suspicious |

## Prompt engineering: a false positive and its fix

The first version of the system prompt asked the model to *"assess whether the email is phishing."* On `ambiguous_01.eml` it returned **phishing, high severity, 0.92 confidence** — a false positive on a pattern that is extremely common in real mail: a legitimate company sending through a third-party email service provider without having finished their DMARC rollout.

Worse, its reasoning asserted *"indicating spoofed sender."* A DMARC failure means the sender was not verified. It does not establish spoofing. The model stated the stronger claim as fact.

False positives are the expensive failure in a SOC. An analyst who finds most alerts are nothing stops reading alerts carefully.

Four changes to the prompt:

1. Defined all three verdicts with explicit criteria, so `suspicious` became a real option rather than an unused label.
2. Stated that authentication failures have innocent causes, and named them — third-party senders, forwarding breaking SPF, incomplete DMARC rollout.
3. Added a **required** `benign_explanation` output field, forcing the model to articulate the innocent hypothesis before committing to a verdict. An alternative you are required to write down is harder to dismiss.
4. Instructed it to separate evidence from inferred intent, targeting the "spoofed sender" overreach directly.

Result:

| Sample | Before | After |
| --- | --- | --- |
| `ambiguous_01` | phishing, high, 0.92 | **suspicious, medium, 0.70** |
| `suspicious_01` | phishing, high, 0.95 | phishing, high, 0.95 (unchanged) |
| `legitimate_01` | legitimate, low | legitimate, low (unchanged) |

One false positive eliminated, both correct verdicts preserved. All three samples are re-run after any prompt change, because changing a prompt to fix one case routinely breaks another.

## Known limitations

Stated plainly, because knowing where a tool stops is part of using it.

- **The IPv4 regex over-matches.** `\b(?:\d{1,3}\.){3}\d{1,3}\b` will match `999.999.999.999`. Proper validation means checking each octet, or using the `ipaddress` module.
- **HTML-only emails yield no IOCs.** `get_body()` returns the first `text/plain` part. A phish sent as HTML only produces an empty body and no extracted indicators. This is a real evasion technique, not a theoretical one.
- **The `Received` chain is not parsed.** The delivery path and HELO mismatches are visible in the samples but unused.
- **Model self-reported confidence is not stable.** Across identical runs at `temperature=0.1`, `confidence` varied by up to 0.10 while `verdict` and `severity` held steady. No automated decision branches on `confidence` for that reason.
- **The model still occasionally overreaches.** Even with the revised prompt it described a `login.php` path as leading to a "credential-harvesting page" — likely true, but not established by the facts. Prompt instructions reduce a failure mode; they do not eliminate it.
- **No mail-flow integration.** It analyzes one `.eml` file at a time from disk. There is no mailbox connector, no queue, no ticketing integration.
- **No IOC enrichment.** Extracted indicators are not checked against any reputation source.

## Security notes

- The API key is read from a gitignored `.env` via `python-dotenv` and never appears in source.
- The model receives extracted facts, not raw email text, which limits prompt-injection exposure. It does not eliminate it — the subject line and IOC strings are still attacker-controlled and do reach the model.
- A future addition worth making: screen the email body with a prompt-injection classifier before any model call.

## Roadmap

- `Received` chain parsing with HELO and reverse-DNS mismatch detection
- Octet validation on extracted IPv4 addresses
- Homoglyph and IDN-homograph detection on sender domains
- Prompt-injection screening of email content before the analyst call
- Benchmark `openai/gpt-oss-20b` against `120b` on the sample set

## Stack

Python 3, [uv](https://github.com/astral-sh/uv) for dependency management, the Groq Python SDK, `python-dotenv`. Model: `openai/gpt-oss-120b` at `temperature=0.1` with JSON mode enforced.
