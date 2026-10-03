# Defensive scope

Use on the bundled public synthetic regression vectors or explicitly authorized
local synthetic test JSON. The tool helps maintainers verify a specified installed
AES-GCM library against public expected behavior and locate individual regressions.
It does not generate exploitation payloads, recover keys, forge signatures, test
online credentials, contact targets, run input code or handle production secrets.

A mismatch establishes only a particular expected-result/output disagreement.
Schema changes, corpus tampering, a harness bug, dependency/version changes and
unsupported parameters must be considered before attributing a cryptographic
vulnerability. Unknown cases, adapter faults and acceptable outcomes are separately
reported. The complete corpus has 27 unsupported valid nonce cases; these remain
OPEN. A matching subset is not complete corpus or whole-library security proof.

Only AES-GCM is implemented. All other algorithms, low-level truncated GCM tags,
throughput benchmarking and general PHP API compatibility are unsupported. No
claim of new research, real exploit, production safeguard impact, applicant identity,
authorization, organization or CVP/provider approval is established by this artifact.
