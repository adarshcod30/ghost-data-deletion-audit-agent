> In this repository the submission files sit at the root (`output.csv`, `log.txt`, `README.md`, `evaluation/`, `code/`). Paths such as `output/submission/...` below refer to the local folder the files were uploaded from.

# Security and privacy review

Scope: the repository at commit 3a28c4b and the four submission artifacts in output/submission. Read-only review first, then targeted fixes. This is a code review plus the scans listed here. It is **not** a security certification, and **no dependency audit was run** (pip-audit or similar was not executed; the only third-party runtime dependency is boto3 1.43.118, pinned in code/requirements.txt, and it is imported only on a cache miss).

| # | Severity | Finding | Where | Reproduction | Impact | Remediation | Regression test | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | Low | A manifest path such as `../x` was joined to the dataset folder and read | `ghostaudit/data.py` load_dataset | add `../outside.json` to evidence_files.csv | read outside the dataset | lexical containment check; a symlinked evidence folder is still allowed | `tests/test_security.py::test_evidence_path_cannot_leave_the_dataset_folder` | fixed |
| 2 | Medium (reliability) | output.csv was written in place, so an interrupted run left a half file | `main.py` cmd_run | kill during write | a truncated file could be submitted | write `output.csv.partial`, then rename | `test_run_leaves_no_partial_file_and_writes_whole_output` | fixed |
| 3 | Low | A symlink to a file inside the dataset folder is followed; evidence files have no size limit; a hostile SQL file could burn CPU (no progress handler) | `data.py`, `evidence.py` `_index_sql` | not reproduced, found by reading | local resource exhaustion from a hostile dataset | size cap and sqlite progress handler | none | open (dataset is trusted participant input) |
| 4 | Low | OCR text of evidence screenshots is cached under `.cache/ocr` with default file permissions | `evidence.py` `_ocr_text` | run once, list `.cache/ocr` | extracted evidence text on disk | folder is git-ignored and `tools/package_submission.py` skips `.cache`; verified absent from code.zip | scan below | accepted, documented |
| 5 | Info | SQL evidence is executed with `executescript` | `evidence.py` `_index_sql` | read | none found: runs in `:memory:` with an authorizer that denies ATTACH, DROP, DELETE and every pragma except foreign_keys, so no evidence file is altered | none | `tests/test_evidence.py` authorizer tests | no defect |
| 6 | Info | Shell and deserialisation | whole package | grep | `subprocess` is called with argument lists (tesseract, pdftotext, 120 s timeout), never `shell=True`; no pickle or yaml.load | none | `test_no_shell_or_unsafe_deserialisation_in_the_package` | no defect |
| 7 | Info | Prompt injection in request text and evidence | `crosscheck.py`, `documents.py`, `prompts/*.md` | classifier cases with "ignore your instructions" and a SYSTEM line (custom_cases.py, model_benchmark.md) | request text reaches a model only inside `<request_text>` tags, the prompt says it is data, and the only thing read back is one boolean. The rule classifier decides. Removing the models gives an identical output.csv (md5 ab46a2f2a455b55a1ce196fe27c15492 with and without `--no-models`) | none | `custom_cases.py` classifier case | no defect |
| 8 | Info | Model-generated ids, operations, states | `documents.py` `validate` | schema tests | the vision reader validates every field against fixed enums and an id pattern, retries once, then rejects; its output is not wired into any prediction. The classifier output is a boolean and cannot affect a row | none | `tests/test_documents.py` | no defect |
| 9 | Low | Cross-case cache leakage | `llm.py` `_key` | read | key is sha256 of model, system prompt, request text, limits and image bytes; the stored value is the model reply only. Two cases share an entry only when their request text is identical, which is correct. No case id or audit time is in a key because none is in a prompt | none | `tests/test_llm.py` | no defect |
| 10 | Low | Cached model replies can hold a short phrase quoted from a request text, and 10 document-reader entries hold fictional dataset emails | `code/llm_cache` | scan below | fictional data only (dataset contract); kept because a cold run needs it | mask on write | none | accepted, documented |
| 11 | Low | Dataset-derived fictional emails appear in `document_benchmark.{md,json,py}` and `tests/test_evidence.py` (about 70 occurrences) | `code/evaluation`, `code/tests` | scan below | the dataset is fictional by contract, but this is dataset content inside code.zip | pseudonymise the benchmark outputs | none | open, minor |
| 12 | Medium | The user's real email address was in the session trace (system context lines, 1,554 times) | agent-trace.zip | scan | personal data in a shared file | redacted in the staged copy | scan below: 0 left, 1,560 markers | fixed in the artifact |
| 13 | Medium | The OAuth `state` and `code_challenge` values from the pasted `aws login` output were in the session file | agent-trace.zip | scan | short-lived login values | redacted in the staged copy; the log.txt entry was already redacted | scan below: 0 left | fixed in the artifact |
| 14 | Info | Diagnostics | `main.py`, exceptions | `test_run_output_names_no_personal_data` | run output has counts, case ids and resource ids only; `runs/audit.jsonl` has 0 `@` characters; evidence errors print file ids and a 120-character cut of the parser message | none | same test | no defect |
| 15 | Info | Secrets in the environment | package | grep `os.environ` | no code reads or prints credentials; boto3 uses its default chain; the cold run was done with an empty HOME and no AWS variables | none | cold run | no defect |

## Secret and personal-data scan of the final artifacts

Run on output/submission after the last rebuild (regexes: AWS access key ids, private key blocks, bearer tokens, `aws_secret_access_key=`, `aws_session_token=`, OAuth `state=` or `code_challenge=` values, the user's real email, common API key shapes):

| Artifact | Result |
|---|---|
| code.zip (879 files, all text files scanned) | no secret patterns. Forbidden content (dataset/, .venv, .cache, runs, csv, zip, .env, .pyc): none. Email addresses are fictional dataset or fixture addresses (finding 11). |
| log.txt | clean |
| output.csv | clean |
| agent-trace.zip | after redaction: 0 occurrences of the real email, 0 OAuth values. The scan covered 7 text files; the session JSONL and the export are the large ones. Binary files (a screenshot) were not scanned. |

Remaining exposures: findings 3, 10 and 11, and any personal content in the trace that is not a pattern above (local file paths such as /Users/adarsh/... remain, and the conversation text is the user's own words). Review the trace before upload.
