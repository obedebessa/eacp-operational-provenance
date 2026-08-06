# OpenTelemetry reference-pipeline comparison

This experiment replays one frozen, namespace-filtered Kubernetes API-server
audit corpus through two pipelines:

1. **OpenTelemetry Collector Contrib 0.158.0**: the `filelog` receiver starts at
   the beginning of the JSONL file, retains each raw line as the exported log
   body, and also populates parsed attributes; a batch processor groups records,
   and the file exporter writes OTLP/JSON.
2. **EACP reference ingestion**: a fresh Python process maps the same JSON
   objects to the 13-field EACP projection and commits them to a new indexed,
   append-only SQLite database.

The container image is fixed to:

```text
ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.158.0
```

The resolved content digest is recorded in each result's `summary.json` and
`environment.json` rather than assumed from the mutable tag.

The canonical `20260806T032418Z` run resolved the image to
`sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5`.

The Collector configuration does **not** map records to the 13-field EACP
schema. It retains each raw audit line as the exported OpenTelemetry log body;
the configured parser also populates attributes, but the post-export EACP
validator operates on the retained body. After export—and outside the timed
interval—the shared validator extracts each body and computes the canonical projection. Thus a
result in which 4,862/4,862 compared values match is a post-export content-
preservation result, not Collector-native semantic-normalization accuracy.

The canonical run retained 374/374 records in both arms. Its post-export
validator matched 4,862/4,862 compared values after normalizing the retained bodies. Median observed time to
validated output was 60.659 ms for EACP and 622.477 ms for OpenTelemetry. For
the Collector this includes host-side reading and JSON decoding of the complete
export, while EACP projection reading occurs later during validation. The
unlike boundaries and output formats make the derived event/s values amortized
completion rates, not ingestion throughput or an implementation ranking.

## Run

Requirements: Python 3.10 or later, SQLite through Python's standard library,
Docker with a running engine, and the fixed Collector image (the script pulls
it if absent).

From the repository root, replay the frozen canonical corpus:

```bash
python3 experiments/comparison/opentelemetry/run_comparison.py run \
  --input data/kubernetes/20260806T031453Z/analysis/public_filtered_audit.jsonl \
  --reference-csv data/kubernetes/20260806T031453Z/analysis/normalized_evidence.csv \
  --output-dir reproduction-output/opentelemetry/replay \
  --trials 10
```

The equivalent Collector container is launched once per trial with the frozen
input mounted read-only, `collector-config.yaml` mounted read-only, and a fresh
output directory:

```bash
docker run --detach \
  --volume <INPUT-DIRECTORY>:/input:ro \
  --volume <CONFIG-FILE>:/config/collector-config.yaml:ro \
  --volume <FRESH-OUTPUT-DIRECTORY>:/output \
  ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.158.0 \
  --config=/config/collector-config.yaml
```

Odd trials run EACP first; even trials run OpenTelemetry first. Each arm is a
clean process/container and writes a new artifact. Temporary SQLite databases
and OTLP/JSON exports are deleted after validation unless `--keep-work` is set.
The frozen public result directory `data/comparison/20260806T032418Z/`
contains only aggregate values, version metadata, checksums, and per-trial
measurements.

## Validation and metrics

Before execution, the runner rejects input containing Kubernetes audit `sourceIPs` fields, Secret
resources, common credential-key names, or recognizable local user paths. It
then validates:

- exact retained event count in every replay;
- no duplicate canonical source identifiers;
- equality with the reference `normalized_evidence.csv` generated separately by the Kubernetes analyzer;
- SHA-256 equality of the order-independent canonical projection; and
- equality for every value in all 13 canonical fields.

The last check uses the shared external normalizer after the Collector export;
it does not attribute the 13-field mapping to OpenTelemetry.

Reported measurements are observed time to validated output, amortized
completion rate for the 374-record replay, output bytes, and bytes per event.
The Collector timer includes Docker startup, batching, polling, and host-side
reading and decoding of the complete export; EACP projection reading occurs
later during validation. EACP writes indexed SQLite, while the Collector file
exporter writes unindexed OTLP/JSON. These asymmetric values are descriptive
operational observations, not ingestion throughput or claims that one
implementation is faster or more space-efficient.

## Scope and limitations

This is a compact laboratory replay, not production-scale validation. The
Collector is used as a real, version-fixed vendor-neutral ingest/parse/export
reference pipeline; it is not represented as a complete provenance query
system. No SQLite-versus-file query benchmark is performed. Ten sequential
paired runs on one host are summarized using minimum, quartiles, median, and
maximum; no independent-population or inferential claim is made. CPU and peak
memory are outside this small experiment.

## Versioned component documentation

- [OpenTelemetry Collector Contrib release 0.158.0](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.158.0)
- [`filelog` receiver 0.158.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.158.0/receiver/filelogreceiver/README.md)
- [file exporter 0.158.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.158.0/exporter/fileexporter/README.md)
