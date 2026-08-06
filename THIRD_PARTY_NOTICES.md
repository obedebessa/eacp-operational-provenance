# Third-party notices

This repository does not relicense third-party projects. The following tools and
images are used to execute or reproduce parts of the artifact but are not
vendored unless a release file explicitly says otherwise.

| Component | Role | Upstream license | Upstream |
|---|---|---|---|
| Python | Benchmark and analysis runtime | Python Software Foundation License | https://www.python.org/ |
| SQLite | Embedded databases used by the benchmark | Public domain | https://www.sqlite.org/copyright.html |
| Pillow | Optional figure rendering | HPND | https://python-pillow.org/ |
| Kubernetes | Audit API and workload target | Apache-2.0 | https://github.com/kubernetes/kubernetes |
| kind | Local single-control-plane Kubernetes environment | Apache-2.0 | https://github.com/kubernetes-sigs/kind |
| OpenTelemetry Collector Contrib | Reference telemetry pipeline | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-collector-contrib |

## Container-image identifiers

- kind node: `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`;
- OpenTelemetry Collector Contrib 0.158.0 resolved image digest: `sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`;
- workload image requested by the canonical manifest: `registry.k8s.io/pause:3.10` (registry manifest-list digest verified during artifact staging: `sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a`; linux/arm64 manifest: `sha256:e50b7059b633caf3c1449b8da680d11845cda4506b513ee7a2de00725f0a34a7`).

Docker, kind, `kubectl`, and the referenced images are prerequisites; their
binaries and image layers are not distributed by this repository.

The canonical workload file retains the tag used by that run; the registry
digests above document the resolved upstream artifact checked during staging.
