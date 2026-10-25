> In this repository the submission files sit at the root (`output.csv`, `log.txt`, `README.md`, `evaluation/`, `code/`). Paths such as `output/submission/...` below refer to the local folder the files were uploaded from.

# Reliability and performance review

Environment: Apple M4, macOS (Darwin arm64), Python 3.13.7, tesseract and poppler from Homebrew. Inputs: the real dataset (518 requests, 94 evidence files). Measured with `/usr/bin/time -l`. Nothing below is estimated.

| Measurement | Result | Command |
|---|---|---|
| Cold run from the unzipped code.zip, empty HOME, no credentials, no OCR cache | 4.82 s, peak memory 84 MB | `env -i PATH=$PATH HOME=<empty> /usr/bin/time -l python code/main.py run` |
| Warm rerun (OCR cache present) | 0.50 s, 50 MB | same |
| `--no-models` | 0.44 s, 48 MB | `python code/main.py run --no-models --output x.csv` |
| Stage timing, warm | load 0.014 s, index 0.209 s, linking and workflow 0.075 s, answer 518 cases 0.065 s (0.13 ms per case), serialisation 0.003 s, model stage 0.065 s | in-process timing script |
| Where the cold time goes | about 4.3 s is OCR of the 11 screenshots (the difference between cold and warm); everything else is under 0.5 s | derived |
| Model calls in the final run | 750 (375 per model), all served from the shipped cache, 0 live | `runs/usage.json` |
| Tokens (as recorded at first call) | 467,047 input, 26,555 output | `evaluation/usage_report.md` |
| Estimated cost | 0.2586 USD at list price; 0.0005 USD per request | same |
| Error rates | 0 unusable model answers of 750; 0 contract problems in 518 rows | run output |
| Determinism | output.csv md5 ab46a2f2a455b55a1ce196fe27c15492 on every run this session (repo, cold unzip, `--no-models`, after each fix); hash-seed test passes | `md5 -q output.csv`, `tests/test_pipeline.py::test_output_is_identical_across_python_hash_seeds` |

No optimisation was made: the pipeline already parses each evidence file once into an index, the answer stage is 0.13 ms per case, and the only slow step (OCR) is cached by content hash. Speeding it up would add risk for no gain.

## Failure behaviour (reproduced on synthetic data, `code/evaluation/adversarial_attacks.py`)

| Situation | Behaviour | Evidence |
|---|---|---|
| A file in the manifest cannot be parsed, or parses to no records | the run stops with the file id; no output is written | E1, E1b |
| A manifest path leaves the dataset folder | the loader stops | `test_security.py` |
| Interrupted run | output is written to `.partial` and renamed, so no half file; the previous output.csv is untouched until the rename | `test_security.py` |
| Rerun after a partial failure | stateless: every run recomputes from the inputs; only the OCR cache and model cache persist and both are keyed by content | code reading, `evidence._ocr_text`, `llm._key` |
| Provider failure or rate limit | `llm.py` retries throttling, timeout and 5xx errors at most 3 times with exponential back-off, then raises `LLMUnavailable`; the model stage never changes a row, so a failure cannot create a duplicate or a contradictory decision | code reading; **not injected in a test** |
| Corrupt cache entry | not tested; a bad JSON file would raise during the model stage (after output.csv is written) | NOT VERIFIED |
| Tesseract or pdftotext missing | the index raises `EvidenceIndexError` and no output is written | code reading; not run without the tools |

## Remaining operational failure modes

1. If tesseract or poppler is missing the run stops (documented in the README prerequisites).
2. The model stage runs after output.csv is written, so a cache corruption fails the command after a valid file exists; use `--no-models` to skip it.
3. Provider fault injection and concurrent runs were not tested.
4. Dependency drift: only boto3 is pinned; pytest and Python are not. The deterministic path uses the standard library only.
5. `pip install -r code/requirements.txt` from a fresh venv was not re-run in this review (the cold runs used the existing venv's interpreter).

**Can the output be regenerated from a clean checkout?** Yes for the shipped path: unzip code.zip beside the dataset, run `python3 code/main.py run`, and the file is byte-identical (verified from an unzipped copy with an empty HOME, 4.8 s). The fresh-venv install step is not verified.
