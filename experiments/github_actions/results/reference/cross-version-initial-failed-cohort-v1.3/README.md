# Initial predeclared cross-version cohort — preserved failure

All nine separately triggered first attempts at protocol commit
`15d72da095a0c7640b9318b50b28728e76d68928` concluded `failure`. The outcome
records in this directory preserve the GitHub run, job, and step metadata for
every predeclared tag; no failed run was replaced or deleted. A capture-time
workflow-runs query also records that each exact tag had one invocation.

For every run, a minimized failed-log observation retains two exact markers in
order: Kubernetes client/server/kubelet version validation and the later
three-row lifecycle assertion. The complete failed log is not retained; only
its SHA-256 and byte count accompany those allowlisted lines. GitHub log and
workflow-run API text are locally captured public observations, not signed
origin records.

The assertion expected three GitHub evidence rows while only the run and
current job could exist. The third row represents the uploaded artifact, which
GitHub creates after the in-job experiment exits. The assertion was therefore
placed at the wrong lifecycle boundary. No evidence archive was uploaded, so
this cohort does not satisfy the predeclared end-to-end criteria and is reported
as `failed`, not as a partial technical success.

A separately predeclared corrective cohort must use new immutable tags and a
new protocol commit. These nine outcomes remain part of the public record.
