# Evaluation protocol

Frozen before any scoring code was written and before either tool was run against
`tests/fixtures/eval_repo/`. The git history is the evidence for that ordering: this file is
committed on its own, with `tools/evaluate.py` not yet in the repository.

Changing anything here after seeing results would mean choosing the rule that flatters the
tool. If a rule turns out to be wrong, the change is made in a later commit **and both sets
of numbers are reported**.

## 1. What is being measured

`tests/fixtures/eval_repo/` — 15 modules, 363 lines — against
`tests/fixtures/eval_repo/GROUND_TRUTH.json`, 56 entries and 18 negatives, written by reading
the samples line by line and committed in `5461797` before either tool saw the directory.

Ground truth records what is **cryptographically true** at each line. It is not a prediction
of any tool's output.

## 2. Facts, and what counts as finding one

Each ground-truth entry yields **one algorithm fact**. An entry that also carries a
`weakness` field yields **one additional weakness fact at the same line**, because two
separate things are true there: an algorithm is in use, and its guarantee is switched off.

This is deliberately tool-neutral. CryptoLens reports the second as a distinct algorithm name
(`TLS-unverified`); Bandit reports it as `B501`. Both earn the same credit, and a tool that
reports neither takes the same false negative.

**Primary metric — call-site granularity.** A finding matches an algorithm fact when
`(relative_path, line, normalize_algorithm(algorithm))` is equal on both sides. Line matching
is exact. Each ground-truth entry refers to one `ast.Call` node; where a call spans lines and
an inner call names the algorithm, both nodes are separate entries and each is matched at its
own line.

**Secondary metric — file granularity.** `(relative_path, normalize_algorithm(algorithm))`
as a set. "Did it notice AES in this file at all", which is more forgiving and arguably
closer to what a reader wants from an inventory. Both are reported.

**FP** — a finding matching no algorithm fact and no weakness fact.
**FN** — a fact no finding matched.

A finding on a line listed in `negatives` is an FP and is **also** counted separately, since
those lines were baited deliberately and are the honest test of a false-positive rate.

## 3. Normalisation

`cryptolens.detectors.normalize.normalize_algorithm`, applied identically to ground truth and
to both tools. It canonicalises spelling (`sha256` -> `SHA-256`); it does not map one
algorithm to another.

## 4. Scoring Bandit fairly

Bandit is a linter for insecure patterns, not a cryptographic inventory. Scoring it against a
full inventory measures it on a task it was never built for, and reporting only that number
would be a strawman. Two figures are reported:

- **Full ground truth** — the inventory gap, which is the thing this project claims to fill.
- **Bandit's own remit** — the subset of ground-truth facts covered by its documented checks:
  weak hash (`B303`, `B324`), insecure cipher and mode (`B304`, `B305`), weak key size
  (`B505`), certificate validation disabled (`B501`). This is the comparison on Bandit's own
  ground and it is the one that matters for "why not just use Bandit?".

Bandit reports issue types, not algorithm names, so an algorithm is recovered from
`issue_text` by a fixed table declared in `tools/evaluate.py`. Where the text names an
algorithm it is used; where it names only a weakness the result is matched as a weakness fact.
Any Bandit result whose check is outside the list above is excluded from its FP count rather
than held against it, because those checks are about something else entirely.

## 5. Reported separately, never folded into precision

- **Attribute error rate** — among detection true positives, the share whose `purpose`
  disagrees with ground truth. Entries whose ground-truth purpose is `unknown` are excluded,
  since "not determinable from this line" cannot be got wrong.
- **Purpose-awareness failures** — ground-truth entries with `security_relevant: false`
  (a real algorithm used for something that is not a security decision) that the tool grades
  `HIGH` or worse. `web/caching.py` uses MD5 three times as an ETag and a cache key;
  CryptoLens has no data flow and is expected to fail all three.
- **Precision at confidence thresholds** — all findings, then `confidence >= 0.5`, then
  `>= 0.9`. The project reports uncertain cases at lowered confidence rather than dropping
  them (principles 5 and 6), so precision over everything is expected to be the worst of the
  three. If the field is doing real work, precision should rise with the threshold; if it does
  not, the field is decoration and that should be visible.

## 6. Sensitivity

Every metric is computed twice: over all entries, and excluding the six marked
`marginal: true` — entries a reasonable expert could omit. Reporting both removes the
temptation to pick whichever set reads better.

## 7. Also recorded

Scan wall-clock time on a repository of known size, and test coverage.
