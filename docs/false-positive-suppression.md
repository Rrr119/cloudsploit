# False-Positive Suppression, Confidence Grading and Audit

This document describes the false-positive (FP) suppression framework added
on top of the existing CloudSploit plugin pipeline. No plugin code changes
are required: every existing plugin keeps its `run(cache, settings,
callback)` contract and its `status` semantics (0 OK, 1 WARN, 2 FAIL,
3 UNKNOWN).

## Components

| Module | Responsibility |
| --- | --- |
| `postprocess/tagIndex.js` | Indexes resource tags from the collection cache by ARN/resource id |
| `postprocess/fpSuppression.js` | Evaluates tag + time-window suppression rules against plugin results |
| `postprocess/confidence.js` | Assigns a confidence score/level to every alert without changing its status |
| `postprocess/audit.js` | Records every suppression hit as a JSONL audit trail and a summary |

The legacy regex `--suppress pluginId:region:resourceId` flag continues to
work unchanged. The new framework is additive and only activates when
`--fp-rules` is provided.

## Rule format

Rules live in a JSON file (see `postprocess/fp-rules.example.json`):

```json
[
    {
        "id": "fp-pentest-ssh",
        "reason": "Authorized penetration test jump box",
        "plugin": "openSSH",
        "region": "*",
        "resource": "arn:aws:ec2:.*:security-group/.*",
        "tags": {"fp-acknowledged": "true"},
        "statuses": [1, 2],
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-12-31T23:59:59Z",
        "enabled": true
    }
]
```

- `tags` (required): every key/value pair must match the resource tags.
  Values support exact match, `*` (any value) and glob wildcards such as
  `temp-*`.
- `start` / `end` (optional): ISO-8601 time window. A rule only matches
  inside the window; expired rules automatically revert to alerting so a
  forgotten rule can never hide a real issue indefinitely.
- `plugin` / `region` / `resource` (optional): further narrowing; `*` or
  omission means "any". `resource` is a regular expression.
- `statuses` (optional): defaults to `[1, 2]` (WARN/FAIL).

### Safety invariants

- UNKNOWN results (status 3, collection errors) and OK results (status 0)
  are never suppressible, so data-collection failures stay visible.
- Rules without tags, with invalid time windows or invalid regexes are
  rejected at load time and reported as invalid instead of failing the scan.
- Tag lookup is driven by the collected cache (for example EC2
  `describeSecurityGroups`/`describeVolumes` tags and S3
  `getBucketTagging`), matched by ARN with a resource-id suffix fallback for
  partition/account differences.

## Confidence grading

Every result receives a `confidence` annotation with a numeric `score`
(5-100), a `level` (`high` / `medium` / `low`; `unknown` for status 3) and
the human-readable `factors` behind the grade. Grading starts from the
plugin status, is strengthened by broad-exposure wording (for example
`0.0.0.0/0`, "unencrypted") and adjusted when risk-acceptance tags such as
`fp-acknowledged` or `exception-approved` are present. Plugins may
optionally add a numeric `confidence_adjustment` hint; this is not required
and existing plugins need no modification.

## Usage

```bash
# Suppress matching alerts and write an audit trail
node index.js --config config.js \
  --fp-rules postprocess/fp-rules.example.json \
  --fp-audit fp-suppression-audit.jsonl \
  --json results.json

# Dry run: evaluate/audit rules but keep every alert
node index.js --config config.js \
  --fp-rules postprocess/fp-rules.example.json \
  --no-fp-suppress
```

When `--fp-audit` is omitted but `--fp-rules` is set, audit records default
to `fp-suppression-audit.jsonl`. JSON and CSV outputs include the new
`confidence`, `suppressed` and `suppression` fields (appended after the
existing fields to preserve consumer compatibility); the console table
gains `Confidence` and `Suppressed` columns.

## Audit record

Each suppression hit appends one JSON line:

```json
{
  "event": "suppression_hit",
  "ruleId": "fp-pentest-ssh",
  "reason": "Authorized penetration test jump box",
  "plugin": "openSSH",
  "region": "us-east-1",
  "resource": "arn:aws:ec2:us-east-1:111122223333:security-group/sg-fp-001",
  "status": 2,
  "message": "Security group: ... has SSH:22 open to 0.0.0.0/0",
  "matchedTags": {"fp-acknowledged": "true"},
  "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
  "evaluatedAt": "2026-06-15T00:00:00.000Z"
}
```

## Acceptance evidence

The acceptance harness under `tests/fp-suppression/` runs three unmodified
production plugins (`openSSH`, `ebsEncryptionEnabled`, `bucketEncryption`)
against a labeled synthetic environment with both real issues and
acknowledged false positives:

```bash
npm run fp:report       # printable quantified report
npm run test:fp-acceptance
```

Acceptance criteria enforced by the tests:

- False-positive rate drops for every one of the three plugins (baseline
  57.1% overall to 0% on the fixture data).
- Zero missed labeled true positives and zero suppressed UNKNOWN results.
- One audit record per suppression hit containing rule id, matched tags,
  time window and evaluation timestamp.
