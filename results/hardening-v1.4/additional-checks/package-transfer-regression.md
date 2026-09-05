# Final packaging regression checks

Author-executed local checks after the measured engineering source commit. These
change packaging and its tests, not the collection/storage campaign results.
No external reproduction or hosted run is established.

Code identities at execution:

```text
f26a8c793cf2a00588b42814ceb6260ab8f34156b3eb44a6ccc3e43d0f8be95b  scripts/package_hardening_review.py
ffa49027f8e4722468f81f13973ade0f5746e7b05f4e0b0ced841b0384e7af7e  tests/test_review_package.py
```

Python 3.12.14 on the same local host as the main validation. Both commands
returned exit code 0. Output below was captured from the actual executions.

Command: `python3 -B -m unittest discover -s tests -p test_review_package.py -v`

```text
test_dirty_source_is_rejected_without_publishing_outputs (test_review_package.ReviewPackageTests.test_dirty_source_is_rejected_without_publishing_outputs) ... ok
test_existing_destination_archive_or_checksum_is_never_overwritten (test_review_package.ReviewPackageTests.test_existing_destination_archive_or_checksum_is_never_overwritten) ... ok
test_fresh_clone_manifest_failure_cannot_publish_an_archive (test_review_package.ReviewPackageTests.test_fresh_clone_manifest_failure_cannot_publish_an_archive) ... ok
test_full_dotted_version_archive_contains_fresh_clone_verified_exact_source (test_review_package.ReviewPackageTests.test_full_dotted_version_archive_contains_fresh_clone_verified_exact_source) ... ok
test_shallow_repository_rejects_before_historical_lookup_or_destination_creation (test_review_package.ReviewPackageTests.test_shallow_repository_rejects_before_historical_lookup_or_destination_creation) ... ok

----------------------------------------------------------------------
Ran 5 tests in 2.079s

OK
```

Command: `python3 -B -m unittest discover -s tests -q`

```text
----------------------------------------------------------------------
Ran 126 tests in 3.542s

OK
```

The 126 cases include the same 121 root cases already measured plus five new
packaging cases. Repeated execution is not an additional distinct case. The
fixtures use actual local bundles and clones, not external GitHub operations.
