# Local validation evidence

Date: 2026-10-02, Asia/Tokyo. The acceptance-gate JSON fixes the official C2SP 40hex
commit, full vector and license/schema hashes, cryptography/transitive versions and
local wheel hashes before new runtime code. The corpus was not edited/subselected.

Actual full run: CPython 3.14.6/macOS arm64, cryptography 47.0.0,
OpenSSL 4.0.0 14 Apr 2026. 316 cases/45 groups: 202 valid matched, 87 invalid
matched, 27 valid skipped, zero mismatches/errors and zero acceptable cases in this
particular corpus. 491 crypto calls attempted. Every tcId has a ledger record.
OPEN honestly preserves unsupported nonce coverage.

Targeted tests exercise actual normal vs bad-tag execution, expected plaintext and
encryption comparison, mislabeled invalid acceptance, acceptable real acceptance/
authentication rejection and erroneous output, zero-IV API-boundary rejection,
unsupported nonce/key/tag/algorithm skips, constructor/adapter errors and version
drift, full count/ID/accounting invariants, repeatability, duplicate keys/IDs, every
schema/hex/width/count/type/flag gate and data/operation/report budgets. Malformed
files, changed snapshots, URLs/stdin/@list/symlink/FIFO/directory inputs cannot be
clean. Input bytes remain unchanged; secrets/comments/paths/exception text are
absent from output. Network/process mocks forbid side effects and legacy flags fail.

A fresh consumer virtual environment installs the exact built wheel and pinned
library wheels offline, with PYTHONPATH unset and work directory outside source.
It reruns the targeted suite, whole corpus and CLI variants. Installed runtime/data
bytes equal reviewed source and wheel bytes. Wheel/sdist retain complete MIT and
unchanged two Apache texts, NOTICE and provenance; sdist also preserves tests,
package/CI definitions and review evidence. Actual counts/checks are in evidence;
final distribution hashes live in the external engineering JSON to avoid a circular
package self-hash claim.

All new runtime/tests/dependency specifications/package/CI/docs/notices are read in
full; the large unchanged data file is hash/schema/case-run validated, not claimed as
independently authored or manually rederived. Dependency API/source/license review
is scoped to the recorded files/ranges; entire dependencies were not fully audited.
Hosted CI and other Python/platform combinations were not run here. Application
eligibility and whole-library security remain OPEN even for matching cases.
