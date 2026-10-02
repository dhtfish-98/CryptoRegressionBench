# CryptoRegressionBench

Offline, bounded AES-GCM regression using **real cryptography 47.0.0 AESGCM
calls** and one complete fixed C2SP/Wycheproof v1 corpus. It validates the corpus,
executes supported cases, checks expected plaintext and encryption output, and
reports every tcId without printing keys, plaintext, ciphertext or raw metadata.
It never implements AES/GHASH itself or evaluates input as code.

This independently written AI-assisted runner adds actual library execution and
fault accounting to the selected PHP Loader/Provider reference. It does not import,
wrap or mechanically translate that library. [ORIGIN](ORIGIN.md) identifies the
selected source audit and attribution; [DEFENSIVE_SCOPE](DEFENSIVE_SCOPE.md) limits
claims. Application eligibility and whole-library security remain **OPEN**.

## Run

```sh
python -m pip install .
crypto-regression-bench
python -m crypto_regression_bench
crypto-regression-bench /explicit/local/aes_gcm_test.json
```

Python 3.11+. Default: the bundled unchanged public corpus. Optional argument:
exactly one explicit local regular JSON file. No stdin, URL, archive, directory
search, composer vendor discovery, automatic updates, plugin, external schema,
network, subprocess, credential validation or report/config writes. Downloading
fixed public research/dependency artifacts was an engineering preparation step;
the installed runtime makes no network calls and executes no input code.

CLI emits deterministic JSON on stdout. Exit 0 PASS, 1 FAIL for a demonstrated
expected-result/output mismatch, 2 OPEN for incomplete/unknown review. A FAIL takes
priority over an OPEN. An edited local corpus can run but retains unverified origin
and OPEN even when its cases match; a byte-for-byte local copy of the fixed corpus
has the same official identity and report as the bundled file. Fingerprints identify
evidence; they do not anonymize its contents.

## Frozen corpus and actual result

C2SP/Wycheproof commit `3fa63dd0344abb611f1fb1d77e119938603ea230`, full
`testvectors_v1/aes_gcm_test.json`, 213,177 bytes, SHA-256
`985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7`.
The preparation gate fixed this revision, file/schema/license hashes, library
version and local dependency wheel hashes before new runtime implementation.
Complete source/reference Apache texts and the unchanged public data ship in both
packages; new code is MIT. No upstream NOTICE file exists at this fixed corpus tree.

On local CPython 3.14.6/macOS arm64 with cryptography 47.0.0 and its actual backend
**OpenSSL 4.0.0 14 Apr 2026**, all 316 tcIds from 45 groups are accounted for:

| Expected category | Total | Matched | Skipped | Mismatched/error |
| --- | ---: | ---: | ---: | ---: |
| valid | 229 | 202 | 27 | 0 |
| invalid | 87 | 87 | 0 | 0 |
| acceptable | 0 | 0 | 0 | 0 |

491 actual encryption/decryption attempts were made. The 27 skips are valid
1/2/4/6-byte or 257-byte nonce cases outside the pinned API's 8–128 byte range.
The complete corpus run therefore returns **OPEN**, with all supported cases
matching; it does not claim every GCM parameter is supported. This corpus contains
zero acceptable cases. Separate regression fixtures exercise legitimate acceptable
acceptance/rejection and erroneous output accounting; they are labeled local
synthetic counterexamples, not additions to the official corpus.

## Execution contract

AES keys: 128/192/256 bits. Tags: exactly 128 bits. Supported nonce API range:
8–128 bytes. Other parameter sizes are individually skipped with tcId/location and
OPEN. The six published invalid zero-length nonce cases are actually passed to
AESGCM.decrypt and counted as known parameter-boundary rejections when it raises
ValueError. Constructor errors and ValueError for supported inputs remain ERROR;
they never count as a successful authentication rejection.

For valid cases, real decryption must return exactly `msg` and real encryption must
return exactly `ct + tag`. Invalid cases run decryption; InvalidTag or the precisely
known zero-IV boundary rejection matches, while any successful decryption fails.
Acceptable cases may be rejected by authentication, or may succeed with matching
plaintext and encryption output; an accepted wrong output fails. Acceptable
rejection runs decryption only. Arbitrary exceptions, unsupported backend, missing
library, non-byte outputs and version drift are ERROR with OPEN. The public CLI
has one fixed adapter; it does not load user-selected adapters or code.

Reports separate `expected_results.valid/invalid/acceptable` from
`execution_results.matched/mismatched/acceptable/skipped/error`. Each case preserves
tcId, numeric group/index, JSON location, expected result, observed decryption and
encryption labels, actual attempted-operation count and fixed reason. All cases
count once, including skips/errors. An unexpected whole-adapter call failure makes
`operation_count_complete` false because its internal call count cannot be known.
The report records actual library/OpenSSL/Python/platform identity. No real key
values, input paths, comments, unknown flags, raw source metadata or exception
messages are emitted. No plaintext/ciphertext digest is emitted either.

## Schema and limits

A strict manually implemented profile of the frozen `aead_test_schema_v1.json` and
`common.json` checks root/group/case/source/note structure and types, expected-result
categories, duplicate JSON keys, duplicate tcIds/flags, declared case count, exact
hex bytes, group bit widths and this AES-GCM profile's equal message/ciphertext
lengths. Unknown schema/group types/fields abort with OPEN before any case runs.
Unknown algorithms are explicitly skipped. Known flags must be in the frozen
8-name set and present in notes; newly declared unknown flag/notes remain OPEN.
This is stricter than a general-purpose Wycheproof schema validator, and does not
promise support for other primitives or all future v1 additions.

Limits may be tightened via library `Limits`: 1 MiB input, 12 JSON nesting levels,
30,000 JSON nodes including keys, 32,768 characters/string, 256 groups, 2,048 cases,
16 KiB per decoded field, 1 MiB aggregate decoded bytes, 4,096 crypto attempts and
1 MiB JSON report. Limits cannot be raised; bool/wrong types are rejected. Nesting
is preflighted before JSON decoding. Case/byte/shape limits abort before execution;
operation budgets skip remaining cases honestly. Report reduction preserves totals
and the first mismatch, marks detail incomplete and adds OPEN. These are data and
operation budgets; no hard wall-clock interruption of a native crypto call is
claimed.

Only the final input path component rejects symlinks with O_NOFOLLOW where
available; parent components use normal OS resolution. Non-regular files/FIFOs are
rejected without blocking where O_NONBLOCK is available. Snapshot size/time/identity
and full byte length are checked before/after read. Input bytes remain unchanged.

## Validation

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python -m build --no-isolation
```

[VALIDATION](VALIDATION.md) and `evidence/` record actual corpus execution, targeted
counterexamples, source review, fresh offline installed consumer checks and full
package/source/license identity. CI defines Python 3.11/3.14 jobs; hosted CI was not
run here. Only the local interpreter/platform stated in evidence was executed.

Primary references: [fixed C2SP corpus](https://github.com/C2SP/wycheproof/blob/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1/aes_gcm_test.json),
[fixed schema](https://github.com/C2SP/wycheproof/blob/3fa63dd0344abb611f1fb1d77e119938603ea230/schemas/aead_test_schema_v1.json),
[cryptography 47.0.0 AESGCM documentation](https://cryptography.io/en/47.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
and [pinned adapter boundary source](https://github.com/pyca/cryptography/blob/47.0.0/src/rust/src/backend/aead.rs#L629).
Only selected dependency API/source ranges were read; this is not a full audit of
cryptography, OpenSSL, Rust, cffi, pycparser or their supply chain.
