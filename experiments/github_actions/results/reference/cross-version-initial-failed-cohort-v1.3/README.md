# Initial predeclared cross-version cohort — preserved failure

All nine separately triggered first attempts at protocol commit
`15d72da095a0c7640b9318b50b28728e76d68928` concluded `failure`. The outcome
records in this directory preserve the GitHub run, job, and step metadata for
every predeclared tag; no failed run was replaced or deleted.

The runs reached exact Kubernetes client/server/kubelet validation and the
controlled workload. They then failed an in-job assertion that expected three
GitHub evidence rows. At that point only the run and current job can exist; the
third row represents the uploaded artifact, which is created after the in-job
experiment exits. The assertion was therefore placed at the wrong lifecycle
boundary. No evidence archive was uploaded, so this cohort does not satisfy the
predeclared end-to-end criteria and is reported as `failed`, not as a partial
technical success.

A separately predeclared corrective cohort must use new immutable tags and a
new protocol commit. These nine outcomes remain part of the public record.
