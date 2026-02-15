# 🔍 LeakTrace

**PR-level sensitive data leak detection engine.** Catches password hashes in API responses, DB connection strings in error pages, and credit card numbers in log statements — before they ship to production.

## 🔥 The Problem

- `model.to_dict()` silently includes `password_hash` in API responses
- Flask error handlers expose full PostgreSQL connection strings
- `log.info(f"processing {request.body}")` writes credit card numbers to Datadog
- **PCI-DSS violations cost $100K–$500K per incident**

## 🚀 Quick Start

```bash
# Install
go install github.com/openkickstart/leaktrace@latest

# Scan your Python codebase
leaktrace ./src

# JSON output for CI integration
leaktrace --format json ./src

# Use in CI — exits non-zero when leaks found
leaktrace --exit-code 1 ./src
```

## 📊 Example Output

```
🔴 app/views.py:42 [CRITICAL] 'db_pass' (from env-var) flows to http-response
   env-var → http-response (var: db_pass)

🔴 app/utils.py:17 [HIGH] sensitive 'password' exposed via log
   password → log (var: (direct))

❌ 2 sensitive data leak path(s) found
```

## 💰 Pricing

| Feature | Free | Pro $79/mo | Enterprise $499/mo |
|---|---|---|---|
| CLI scanning | ✅ | ✅ | ✅ |
| Python taint analysis | ✅ | ✅ | ✅ |
| JSON output | ✅ | ✅ | ✅ |
| SARIF output | ❌ | ✅ | ✅ |
| GitHub Action + PR comments | ❌ | ✅ | ✅ |
| JS/TS/Go/Java support | ❌ | ✅ | ✅ |
| Cross-file taint tracking | ❌ | ✅ | ✅ |
| Custom source/sink rules | ❌ | ❌ | ✅ |
| PDF compliance reports (PCI/SOC2) | ❌ | ❌ | ✅ |
| SSO/SAML + audit trail | ❌ | ❌ | ✅ |
| Slack/PagerDuty alerts | ❌ | ❌ | ✅ |
| SLA support | ❌ | ❌ | ✅ |

## 🤔 Why Pay?

**One PCI-DSS violation = $500K fine.** LeakTrace Pro at $79/mo pays for itself the first time it blocks a single leaked credit card field from reaching production logs.

- **Semgrep/SonarQube** find code smells — LeakTrace finds **data flow paths** from sensitive sources to output sinks
- **GitLeaks** finds hardcoded secrets — LeakTrace finds **runtime data leaks** through serialization, logging, and error handling
- **Single binary, <50ms scan time** — no JVM, no Docker, no config files

## 🔧 GitHub Actions

```yaml
- uses: openkickstart/leaktrace-action@v1
  with:
    path: ./src
    format: sarif  # Pro feature
```

## License

BSL 1.1 — Free for teams ≤5. Commercial license required for larger teams.
