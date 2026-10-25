> In this repository the submission files sit at the root (`output.csv`, `log.txt`, `README.md`, `evaluation/`, `code/`). Paths such as `output/submission/...` below refer to the local folder the files were uploaded from.

# Final release review

Status words: PASS (verified with evidence), FAIL (violated), NOT VERIFIED (cannot be proven with what is available here). Evidence was produced in this session on commit 3a28c4b; paths are in the submission folder or the repository.

## A. Contract compliance

| Check | Status | Evidence |
|---|---|---|
| 518 rows, one per request, no extra or duplicate case | PASS | `python3 code/evaluation/contract_check.py output/submission/output.csv` (standalone, shares no code with the verifier) |
| Exact header `case_id,deletion_status,steps_json`, LF endings, no BOM | PASS | same |
| Statuses, step keys, numbering, phase order, operation to phase and state pairs | PASS | same |
| NOT_APPLICABLE rows have `[]` | PASS | same, 10 rows |
| Valid CSV and JSON | PASS | same |
| Evidence ids exist and are dated at or before audit_at | PASS | same; also `ghostaudit/verify.py` run on every row |
| Future work (remediation, verification in INCOMPLETE rows) has empty evidence_id | PASS | same |
| Cited file actually names the resource or covers the system | PASS | verifier check added this session; 518 rows pass; 66 of 66 sample citations support (`metric_audit.md`) |
| Row order: natural numeric (case_2 before case_10) versus plain string order | NOT VERIFIED | the spec says "sort by case_id"; the sample file's ids are zero padded (case_01), so it cannot tell the two apart; a grader that joins on case_id is unaffected, one that checks string order would flag it |
| Policy treatment correct on the hidden 518 | NOT VERIFIED | no reference answers; on the 32 samples DELETE, REDACT, ANONYMIZE, RETAIN, BLOCK_RESTORE and DISABLE_FLOW all score precision 1.0 (`metric_audit.md`) |

## B. Decision quality

| Check | Status | Evidence |
|---|---|---|
| Historical identity (old email, old phone, old email hash) | PASS on constructed data | adversarial I1, I3, I3b |
| Look-alike people kept apart | PASS on constructed data | I2, I2b, I5, E2 |
| Secondary copies and recreation paths found | PASS on constructed data | S1, S3, S4 |
| Future evidence ignored, tie and stale-state handling | PASS on constructed data, after fixes | E5, E5b, E6, E6b, E6c |
| No path to a false COMPLETE | **FAIL (known, documented)** | `adversarial_review.md` open defects 1 and 2: 31 linked resources in the real run are left out of their case because their state is unreadable, and 3 cases (case_45, case_61, case_63) have no identifiable resource and are COMPLETE with no steps |
| Hidden-set accuracy | NOT VERIFIED | no labels; all scores are on 32 development samples |

## C. Engineering quality

| Check | Status | Evidence |
|---|---|---|
| Test suite | PASS | `python3 -m pytest code/tests -q`: 210 passed, 1 skipped (a documented open defect), run again from the unzipped archive |
| Deterministic output | PASS | same md5 on every run; hash-seed subprocess test |
| Clean-run reproducibility | PASS | unzipped code.zip next to the dataset, empty HOME, no credentials: byte-identical output, 4.8 s |
| `pip install` from a fresh venv | NOT VERIFIED | not re-run |
| Security and privacy | PASS with open items | `output/reviews/security_review.md`; no dependency audit was run |

## D. Evaluation integrity

| Check | Status | Evidence |
|---|---|---|
| Metrics recomputed independently | PASS | `code/evaluation/independent_metrics.py`: no disagreement with the scorer |
| Denominators and zero cases stated | PASS | `metric_audit.md` (the scorer's 0/0 = 1.0 is documented) |
| At least three additional evaluation cases | PASS, with a caveat | 5 custom cases and 49 adversarial attacks, but written by the same agent that wrote the code, so they are not independently authored |
| Usage report matches the run | PASS | `runs/usage.json` against `evaluation/usage_report.md`; development-time calls are listed separately, not mixed in |
| Limits and failures disclosed | PASS | `evaluation_report.md`, `adversarial_review.md` |

## E. Submission artifacts

| Check | Status | Evidence |
|---|---|---|
| code.zip holds README.md, code/, evaluation/evaluation_report.md, evaluation/usage_report.md | PASS | `unzip -l output/submission/code.zip` |
| No dataset/, nested archives, venv, caches, csv, secrets | PASS | scan in `security_review.md` |
| README setup works | PASS for the run commands, NOT VERIFIED for the venv install line | cold run |
| log.txt has `tool=` and `model=` in every entry | PASS | 30 entries, 30 tool lines, 30 model lines (counted before this file was written); one early entry carries a wrong timestamp, disclosed in the next entry |
| log.txt is a genuine record of the session | PASS as an agent-written log under AGENTS.md; it is not the platform's own transcript | the session JSONL and export are in agent-trace.zip |
| `tool=claude-code` matches the harness name | NOT VERIFIED | I used the value I was running under; I cannot read an authoritative identifier |
| agent-trace.zip complete | NOT VERIFIED | snapshot taken before the final messages; the real email and OAuth values were redacted |
| Interview window opens, submission accepted | NOT VERIFIED | needs the HackerRank site |
| Deadline | the machine clock read 18:11 IST when this work resumed and 18:48 later, after the 18:00 deadline | `date`; whether the platform still accepts a submission is unknown |

## Decision: READY WITH KNOWN RISKS

All mechanical artifact, contract and reproducibility checks pass. The material risks are semantic and documented: possible false COMPLETE in 3 unidentified cases and in cases with 31 unreadable linked resources, no hidden-set measurement, and an unresolved row-order interpretation. The deadline has passed, which is outside what I can fix.

**Please review yourself:** the decision to answer case_45, case_61 and case_63 as COMPLETE with no steps; whether you want plain string order for case ids; agent-trace.zip contents (local paths and your own messages remain); that the upload page accepts the four files.
