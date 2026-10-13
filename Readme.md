# Webhook Discovery

A standalone, standard-library CLI that crawls one authorized website for **potential** webhook receiver endpoints. It starts from the supplied hostname and discovers pages, forms, and same-origin JavaScript dynamically; it does not use a third-party search service or a bundled endpoint list.

## How it works

<p align="center"><img src="docs/workflow.svg" alt="Workflow: repeatedly crawl same-origin pages and scripts until limits are reached, then report redacted candidate endpoints without submitting requests" width="100%"></p>

The crawler makes bounded `GET` requests to the supplied origin only. It follows same-origin page links and reads same-origin script files, repeating that process until its page or request limit is reached. From HTML forms and statically visible JavaScript, it extracts `POST`, `PUT`, and `PATCH` destinations. It never sends those methods or attempts to verify whether a candidate accepts callbacks. Secret-like query values are redacted in displayed URLs.

The discovery flow is:

1. Start at `https://<hostname>/`.
2. Parse each fetched HTML page for same-origin links, receiver-method forms, and script references.
3. Queue newly found pages and inspect referenced same-origin scripts, subject to the configured limits and delay.
4. Extract statically visible request destinations, keep exact-origin matches, redact, and deduplicate them.

## Scope and limitations

Use only with domains you own or are authorized to assess. Discovery is heuristic: a candidate may be an ordinary application API, and an actual webhook may not be linked from crawled pages or visible in JavaScript. Dynamically generated or obfuscated requests, server-side routes, and third-party webhook destinations can be missed. A candidate is not proof that an endpoint is open or is actually a webhook.

The crawler is restricted to the exact HTTPS origin derived from the supplied hostname. Off-origin links and redirects are not followed. Page count, total request count, response size, timeout, and delay are bounded. The default limits are 30 HTML pages and 200 total GET requests, including scripts.

## Requirements

- Python 3.11 or newer
- Network access to the authorized target site
- No third-party Python packages

## Run

From this directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "src"
python -m webhook_discovery.cli example.org
```

Adjust crawl limits:

```powershell
python -m webhook_discovery.cli example.org --max-pages 50 --max-requests 300
```

Print machine-readable JSON:

```powershell
python -m webhook_discovery.cli example.org --json
```

The optional editable install exposes a `webhook-discovery` command:

```powershell
python -m pip install -e .
webhook-discovery example.org --max-pages 50
```

## Tests

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```
