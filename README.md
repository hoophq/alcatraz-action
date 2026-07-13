<div align="center">

# 🪨 Alcatraz PII Scan for GitHub Actions

### Catch PII before it lands in your repo, logs, comments, or issues.

Emails, credit cards, national IDs, secrets: **45 entity types across 12
countries**, detected by [hoophq/alcatraz](https://github.com/hoophq/alcatraz)
right on the runner. No service, no network calls, no models.

</div>

```yaml
- uses: hoophq/alcatraz-action@v1
```

The action scans, annotates the offending lines, posts a **sticky report
comment** on the PR or issue (values masked, never re-published), writes a
step summary, and, by default, fails the check until the PII is removed or
allow-listed.

> [!NOTE]
> Alcatraz detects **PII values present in text**. A PR diff scan catches
> literal PII being committed; a log scan catches PII your code *emitted* at
> runtime. It does not do static taint analysis. To answer "do we log PII?",
> run your tests, capture their output, and scan it (see below).

## Scan PR diffs

Flags PII in the lines a pull request adds. The diff is fetched from the
GitHub API, so no `fetch-depth: 0` is needed.

```yaml
# .github/workflows/pii.yml
name: PII scan
on: pull_request

permissions:
  contents: read
  pull-requests: write   # for the report comment

jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hoophq/alcatraz-action@v1
```

## Scan logs (do we log PII?)

Run your test suite, capture everything it prints, and scan the capture.
Findings mean your code logged PII during execution:

```yaml
  logs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go test -v ./... 2>&1 | tee /tmp/test-output.log
      - uses: hoophq/alcatraz-action@v1
        with:
          mode: files
          paths: /tmp/test-output.log
```

Detection quality follows your test data: alcatraz verifies checksums, so a
Luhn-valid card number is caught while `1234123412341234` is not. Seed tests
with realistic (synthetic but checksum-valid) values.

## Scan PR comments and issues

People paste logs and stack traces into comments. This scans every new or
edited comment/issue body and replies with a masked report when PII is found:

```yaml
name: PII in comments and issues
on:
  issue_comment:                     # comments on issues AND pull requests
    types: [created, edited]
  issues:
    types: [opened, edited]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: hoophq/alcatraz-action@v1
        with:
          mode: comment
          fail-on-findings: "false"  # report, don't red-X the conversation
```

No checkout needed: the body comes from the event payload. The action skips
its own report comments, so it never scans itself in a loop.

## Inputs

| Input | Default | Description |
|---|---|---|
| `mode` | `diff` | `diff` (PR added lines), `files` (paths in `paths`), or `comment` (triggering comment/issue body) |
| `paths` | – | Space-separated files/globs, required for `mode: files` |
| `threshold` | `0.8` | Minimum confidence in `[0,1]`. Raise for precision, lower for recall |
| `entities` | all 45 | Comma-separated entity types to restrict to, e.g. `CREDIT_CARD,EMAIL_ADDRESS,US_SSN` |
| `ignore-entities` | `DATE_TIME,URL` | Entity types dropped as noise |
| `allowlist-file` | – | Repo path with allowed values, one per line (`#` comments ok) |
| `exclude` | `go.sum,*.lock,*.svg,*.min.js,vendor/**,node_modules/**` | Glob patterns of diff paths to skip (`mode: diff`) |
| `comment` | `true` | Post/update the sticky report comment |
| `fail-on-findings` | `true` | Fail the check when PII is found |
| `github-token` | `github.token` | Token for reading the diff and commenting |

## Outputs

| Output | Description |
|---|---|
| `findings` | Number of PII findings |
| `report-file` | Path of the markdown report on the runner |

Use them to build your own follow-up steps:

```yaml
- uses: hoophq/alcatraz-action@v1
  id: pii
  with:
    fail-on-findings: "false"
- if: steps.pii.outputs.findings > 0
  run: echo "PII found, notify the security channel here"
```

## Handling false positives

Create an allowlist file in your repo (e.g. `.pii-allowlist`) with one value
per line: test fixtures, documented examples, seeded demo data.

```
# synthetic fixtures used in tests
4532015112830366
jane@example.com
```

and point the action at it with `allowlist-file: .pii-allowlist`. To narrow
what's detected instead, set `entities` to the types you care about, or tune
`threshold`: the default `0.8` keeps checksum-verified identifiers (score
`1.0`: credit cards, national IDs, IBANs) and drops shape-only matches.
Lower it (e.g. `0.4`) to also catch emails and phone numbers, which score
`0.5`.

## What gets posted

The sticky comment (one per mode, updated in place on every run) shows masked
values only; the action never re-publishes the PII it found:

> ## 🪨 Alcatraz PII scan
>
> **2 finding(s)** in this PR's diff.
>
> | Location | Entity | Value (masked) | Score |
> |---|---|---|---|
> | server/log.go:21 | `CREDIT_CARD` | `45************66` | 1.00 |
> | server/log.go:21 | `EMAIL_ADDRESS` | `ja************om` | 0.50 |

Findings also surface as inline annotations in the PR "Files changed" view
and in the job's step summary. When a later run comes back clean, the sticky
comment is updated to the all-clear instead of lingering stale.

## Versioning

Pin the major tag; it follows the latest release:

```yaml
- uses: hoophq/alcatraz-action@v1
```

Releases are cut automatically on merge to `main`: label the PR with exactly
one of `major`, `minor`, `patch`, or `skip-release` (enforced by the
`PR Release Label Check` workflow). On merge, `auto-release.yml` computes the
next semver from the highest existing release, creates the GitHub release and
tag, and re-points the moving major tag (`v1`).

If you ever need to release by hand, remember to move the major tag too:

```bash
git tag v1.2.1 && git push origin v1.2.1
git tag -f v1 v1.2.1 && git push -f origin v1
```

---

Built on [hoophq/alcatraz](https://github.com/hoophq/alcatraz) by the team
behind [hoop.dev](https://hoop.dev).
