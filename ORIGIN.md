# Source, corpus and contribution attribution

Selected reference: [trailofbits/wycheproof-php](https://github.com/trailofbits/wycheproof-php/tree/86a57669e04a152dbc331fffe0362f3dba7a32f9),
fixed commit `86a57669e04a152dbc331fffe0362f3dba7a32f9`. Fully read selected files:
TestVectorLoader, GenericProvider, AeadProvider, AeadTestVectors, TestResult,
Wycheproof discovery, WycheproofException, composer.json, README and original
LICENSE. Source hashes and line counts are recorded in evidence. Other
algorithms/providers/traits and PHPUnit/build/CI sources were not fully reviewed.
The PHP project loads/flattens vectors and classifies expected results; consumers
provide actual crypto operations. Its loader's upward vendor discovery/cache,
GenericProvider labels/raw metadata and unfixed dev-main vector dependency are
excluded. No PHP runtime implementation is copied, renamed, imported or shipped.

New implementation author and maintainer: dhtfish98. Its contribution is
bounded local snapshot/schema validation, frozen corpus identity, real pinned-library
adapter calls, plaintext and encryption output comparison, precise authentication
vs parameter vs adapter-error accounting, complete case ledger, private reproducible
reports and targeted counterexamples/consumer/package checks. It does not implement
cryptographic primitives and does not claim original discovery of published cases.

Official public synthetic data: C2SP/wycheproof commit
`3fa63dd0344abb611f1fb1d77e119938603ea230`, full AES-GCM v1 vector file. The fixed
C2SP tree inventory was checked for licensing/NOTICE, and the two relevant official
JSON schemas were fully read. All 316 cases were structurally validated, identities
checked and individually accounted in actual execution; their cryptographic values
were not manually audited as original research. The published file remains byte-for-
byte unchanged. Project Wycheproof was originally developed by Google and is now a
community project under C2SP. The complete original Apache-2.0 license is retained.

The unchanged Trail of Bits Apache-2.0 license includes Copyright 2025 Trail of Bits,
Inc. New code's MIT grant does not relicense either source reference or corpus.
NOTICE provides separate attribution; both Apache texts/new MIT and provenance
ship in wheel/sdist. External cryptography/cffi/pycparser packages are separately
installed; their own complete distributed notices were inspected in local dependency
wheels. Those packages are not bundled into/relicensed by this distribution.

AESGCM documentation and selected Rust adapter boundary source at cryptography
47.0.0 were read; only selected portions of dependency implementation were reviewed.
No full cryptography/OpenSSL/Rust/transitive-source audit is claimed. Dependencies
are fixed and actual wheel hashes/backend identity are recorded for the local run.
Do not call the applicant the sole human author of this new code, the author of
Wycheproof/Trail of Bits/cryptography, or a discoverer of the published edge cases.
Whole-library security, actual deployment impact and application qualification are
separate, **OPEN** claims.
