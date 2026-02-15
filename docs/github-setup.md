# GitHub Setup Guide

Integrate LeakTrace into your GitHub PR workflow in 3 steps.

## Step 1: Add the Workflow File

Create `.github/workflows/leaktrace.yml` in your repository:

```yaml
name: LeakTrace PR Scan

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: read

jobs:
  leaktrace:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: openkickstart/leaktrace@v1
        with:
          severity-threshold: high
          format: sarif
          fail-on-leak: 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Commit and push this file to your `main` branch.

## Step 2: Configure the Severity Threshold

LeakTrace supports three severity levels:

| Level | Description | Examples |
|---|---|---|
| `critical` | Sensitive data flows to HTTP responses or exceptions | `password_hash` in `jsonify()`, DB URL in `raise ValueError()` |
| `high` | Sensitive data flows to log statements | `api_key` in `logger.info()` |
| `medium` | Sensitive data flows to print or other outputs | `token` in `print()` |

Set `severity-threshold` to control which findings block the PR:

```yaml
# Block on critical and high (recommended for most teams)
severity-threshold: high

# Block only on critical (lenient — allows log leaks)
severity-threshold: critical

# Block on everything including print statements
severity-threshold: medium
```

To allow leaks to be reported without blocking the PR, set `fail-on-leak: 'false'`.
Findings will still appear in the GitHub Code Scanning tab.

## Step 3: Review PR Check Results

Once configured, every pull request will show LeakTrace results in three places:

### 1. PR Check Status

LeakTrace appears as a required check on your PR. If `fail-on-leak` is `true`,
the check will fail (red ✗) when leaks above your threshold are detected.

### 2. Code Scanning Alerts

When using `format: sarif`, findings are uploaded to GitHub's **Security → Code scanning**
tab. Each finding shows:

- The exact file and line where the leak occurs
- The source (e.g., `password`, `api_key`, `credit_card`)
- The sink (e.g., `log`, `http-response`, `exception`)
- The severity level

### 3. Workflow Logs

Detailed scan output is available in the Actions tab under the LeakTrace job logs,
including the list of files scanned from the PR diff.

---

## Advanced: Custom Workflow with Manual Binary

If you prefer to manage the binary yourself:

```yaml
name: LeakTrace Manual

on:
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install LeakTrace
        run: |
          curl -sSL https://github.com/openkickstart/leaktrace/releases/latest/download/leaktrace_linux_amd64.tar.gz | tar xz
          chmod +x leaktrace
          sudo mv leaktrace /usr/local/bin/

      - name: Scan PR files
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh pr diff ${{ github.event.pull_request.number }} --name-only | \
            leaktrace --diff-only --format text --severity-threshold high --exit-code 1
```

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `gh pr diff` fails | Ensure `pull-requests: read` permission is set and `GITHUB_TOKEN` is available |
| No SARIF results in Security tab | Ensure `security-events: write` permission is set |
| Check passes but you expected failures | Verify `fail-on-leak: 'true'` (must be a string `'true'`, not boolean) |
| Only `.py` files are scanned | LeakTrace free tier supports Python only. Upgrade to Pro for JS/TS/Go/Java |
