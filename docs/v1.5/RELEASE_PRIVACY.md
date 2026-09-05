# Privacy-screened review delivery

The requested policy preserves scientific authorship, attribution required by
licenses, literature citations, public repository identity and historical
cryptographic identities. It suppresses private local paths, private reviewer
identifiers and personal contact details in current distribution copies.

## Original evidence and derivative copies

`PRIVACY_REDACTIONS.json` and `PDF_PRIVACY_REDACTIONS.json` bind each changed
repository file to its original candidate bytes and its distribution bytes.
They contain relative filenames and hashes, never the hidden values. Text changes
remove private path prefixes or reviewer identities, not test outcomes. PDF
changes remove private contact details, not the author's name or scientific text.

Signed TARs, attestation payloads and trust roots are not rewritten. Source truth
and human identity are not inferred from redaction or from a checksum. Earlier
manifests and signatures belong to their original artifacts: a derivative copy
has a new manifest and must not claim the original checksum verifies its bytes.

The review ZIP does not include `.git`, full-history bundles, private input ZIPs,
private mapping policies, or stale checksums for edited reviewer documents.
Its source snapshot is usable for installed-runtime tests. Git-history-dependent
checks require the separately accessible official checkout and are explicitly
distinguished from snapshot integrity checks.

## Scope and limits

This is privacy screening, not anonymization: authorship, public GitHub account,
DOIs and scholarly references intentionally identify the project. No old Git
history, archived tag, third-party cache, existing DOI or old distributed ZIP is
erased. Such removal is a separate, potentially destructive migration; the
current task does not silently rewrite or force-push historical evidence.

The scanner is bounded and reports unsupported/opaque material. Its selected
patterns and private policy are not proof that arbitrary undisclosed personal
data can never exist. The build must stop on unexplained privacy findings. Known
intentionally altered negative-control archives remain failed controls, not a
privacy-success claim. New local verification uses a disposable neutral directory.
