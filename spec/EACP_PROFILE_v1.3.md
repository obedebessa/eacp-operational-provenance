# EACP Profile 1.3

Status: implementable candidate specification, 2026-09-02

This document defines a conservative interchange profile for evidence used in
operational-provenance reconstruction. It replaces the single overloaded
`correlation_id` field with scoped, typed, multivalued links while retaining a
deterministic migration path from the EACP 1.2 13-column CSV projection.

The profile describes evidence and associations. It does **not** establish that
a source told the truth, authenticate a source, prove that an actor caused an
outcome, or prove that two linked observations have a common cause.

## 1. Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are to be interpreted as normative requirements.

An EACP 1.3 record conforms when it:

1. validates against
   [`schema/eacp-core-evidence-record-v1.3.schema.json`](schema/eacp-core-evidence-record-v1.3.schema.json);
2. satisfies the semantic constraints in section 8; and
3. is accepted by the reference validator in
   [`tools/eacp_profile.py`](tools/eacp_profile.py).

The JSON Schemas use JSON Schema Draft 2020-12. The reference tool has no
third-party dependencies; it implements the profile checks directly rather
than claiming to be a general JSON Schema implementation.

## 2. Core evidence record

For a record `r`, the normative evidence tuple is:

```text
T(r) = (
  profile,
  source_type,
  source_id,
  source_ts,
  observed_ts,
  actors,
  service,
  intent,
  policy,
  action,
  outcome,
  source_pointer,
  source_digest?,
  links,
  extensions?
)
```

Unlike the earlier formalization, `source_type` and `source_id` are explicitly
members of the tuple. Their ordered pair is the record's source identity:

```text
source_key(r) = (r.source_type, r.source_id)
```

`source_key` MUST be unique in one evidence collection. An adapter MUST make
`source_id` stable and unambiguous under its `source_type`; a URI is
recommended. If a native identifier is only locally unique, the adapter MUST
embed the necessary account, tenant, cluster, repository, or equivalent scope
in `source_id`.

The required top-level members are:

| Member | Meaning |
| --- | --- |
| `profile` | Literal `eacp.profile/1.3`. |
| `source_type` | Namespaced class of the source observation, such as `github.actions.run` or `kubernetes.audit`. |
| `source_id` | Stable identifier of the source observation under `source_type`. |
| `source_ts` | RFC 3339 timestamp reported by, or derived from, the source. |
| `observed_ts` | RFC 3339 timestamp at which the adapter observed the representation. |
| `actors` | Available actor references, keyed by the roles in section 3; the object can be empty. |
| `service` | Scoped, typed service identity described in section 4. |
| `intent` | Source-preserving description of the intended objective. |
| `policy` | Policy, workflow, rule, or control context reported by the adapter. |
| `action` | Operation observed. |
| `outcome` | Outcome reported or derived by the adapter. |
| `source_pointer` | Locator for the supporting representation. It need not remain reachable. |
| `links` | Zero or more relationship assertions described in section 5. |

An earlier `observed_ts` than `source_ts` is not by itself invalid: source
clocks can be skewed. Implementations MAY warn, but MUST NOT silently rewrite
either timestamp.

## 3. Actor roles

`actors` is an object with zero or more of these properties:

- `initiator`: identity that requested the broader operation;
- `triggering_actor`: identity whose event caused automated execution to start;
- `execution_principal`: identity under which the observed action executed; and
- `attester`: identity that produced an attestation represented by the record.

Each property contains an actor reference with `id`, `type`, and `scope`.
Missing roles MUST be omitted, and an empty object is valid when no actor is
supported by the evidence. An implementation MUST NOT copy a known actor into
every role merely to fill the object. Role labels report the source's or
adapter's evidence, not legal responsibility, human control, or causation.

The permitted actor types are `human`, `service_account`,
`workload_identity`, `automation`, `system`, `unknown`, and `legacy_opaque`.
`legacy_opaque` is reserved for migration when the flat 1.2 `actor` value does
not carry enough information to classify the identity.

## 4. Scoped service identity

`service` contains:

- `id`: identifier inside the declared scope;
- `type`: one of `logical_service`, `application`, `repository`, `workload`,
  `kubernetes_resource`, `cloud_service`, `system`, `unknown`, or
  `legacy_opaque`; and
- `scope`: a typed scope.

A scope is the pair `(type, id)`. Scope types are `global`, `organization`,
`repository`, `account`, `tenant`, `project`, `cluster`, `namespace`,
`environment`, `system`, `custom`, and `legacy_dataset`.

Implementations MUST compare complete service identities
`(service.type, service.scope.type, service.scope.id, service.id)`. They MUST
NOT equate two services solely because their unscoped `id` strings match.
`legacy_opaque` and `legacy_dataset` preserve a value without claiming a type
that the 1.2 row did not contain.

## 5. Typed, multivalued links

Each member of `links` is an assertion with:

- `type`;
- `value`;
- `scope`;
- `evidence_method`; and
- `confidence` only when `evidence_method` is `inferred`.

The standard link types are:

| Type | Intended referent |
| --- | --- |
| `operational_correlation` | Explicit operational hand-off or chain identifier. |
| `vcs_revision` | Version-control revision identifier. |
| `artifact_digest` | Content digest of a delivered artifact. |
| `deployment_uid` | Deployment or workload UID. |
| `workflow_run` | CI/CD workflow execution. |
| `policy_decision` | Policy-engine decision. |
| `incident_id` | Incident record. |
| `trace_id` | Distributed-trace identifier. |
| `recovery_point` | Recovery point or backup identifier. |
| `ticket_id` | Change or work ticket. |
| `custom` | Extension relation; `custom_type` is then required. |

The same record MAY contain multiple link types and multiple values of a type.
This is deliberate: a deployment can refer to a revision, image digest,
workflow run, deployment UID, and incident at once. Within one record, the key
`(effective_type, scope.type, scope.id, value)` MUST NOT be duplicated, even if
two copies claim different evidence methods. `effective_type` is `type` for a
standard link and `custom:<custom_type>` for a custom link.

`evidence_method` has exactly these meanings:

- `source_native`: the source representation directly carried the value;
- `explicit`: the value was explicitly bound by an adapter, operator, or prior
  EACP assertion rather than discovered heuristically;
- `digest_match`: the relationship was established through exact digest
  equality; this method is valid only for `artifact_digest`; and
- `inferred`: a heuristic produced the candidate relationship.

`confidence` is REQUIRED for `inferred`, MUST be greater than zero and no
greater than one, and MUST be absent for every other method. It is a declared
score, not automatically a calibrated probability. The producer SHOULD
document the inference method and its calibration outside the record.

An `explicit` link means that the binding was expressly asserted; it does not
mean source-native, correct, authentic, or causal. Migration uses `explicit`
for a non-empty legacy `correlation_id` because the 1.2 row expressly contains
that assertion, while retaining no basis to relabel it `source_native`.

## 6. Source pointer and optional digest

`source_pointer` is a locator. It does not assert reachability, immutability,
authorization, or retention.

`source_digest` MAY accompany the pointer. It records an algorithm, digest
value, and the representation covered:

- `raw_bytes`;
- `canonical_json`;
- `sanitized_canonical_json`; or
- `adapter_defined`.

For any representation other than `raw_bytes`, `canonicalization` is REQUIRED
and MUST name the exact transformation. A digest can detect that the compared
representation differs from the hashed representation. A digest alone does
**not** authenticate the source, establish who produced it, establish that its
contents are true, or make a causal claim. Authentication requires a separate
trust mechanism (for example, a verified signature and trust policy), which is
outside this profile.

The flat 1.2 `content_hash` is not automatically promoted to `source_digest`:
published adapters used it for different representations. The migration tool
preserves it verbatim under the legacy extension instead.

## 7. Safe resolution and abstention

The reference resolver operates on exact link keys. For a seed record and a
requested link type (and optional scope filter), it:

1. discards inferred links unless the caller explicitly enables them and
   supplies a minimum confidence;
2. returns `missing` with no matches if the seed has no eligible key;
3. returns `ambiguous` with no matches if the seed has more than one distinct
   eligible key; and
4. otherwise returns only records that carry exactly one eligible key in the
   selected type and scope and whose key exactly equals the seed key.

Records that also assert another value in the selected type and scope are
excluded and reported as ambiguous; they are never used as bridges between
groups. `missing` and `ambiguous` responses set `abstained` to `true`,
`selected_link` to `null`, and `matches` to an empty array. The response format
is defined by
[`schema/eacp-link-resolution-v1.3.schema.json`](schema/eacp-link-resolution-v1.3.schema.json).

Safe abstention prevents the reference resolver from silently guessing. It
does not make collisions, malicious identifiers, incorrect explicit bindings,
or upstream source errors impossible.

## 8. Semantic constraints

In addition to JSON Schema validation, conforming collections and tools MUST
enforce all of the following:

1. `(source_type, source_id)` is unique in a collection.
2. All timestamps include a UTC offset (`Z` is permitted).
3. Actor and service identifiers contain no control characters.
4. No two links in a record share the same typed, scoped key (including
   `custom_type` when `type` is `custom`).
5. `digest_match` is used only with `artifact_digest`, whose value is formatted
   as `sha256:<64 lowercase hex>` or `sha512:<128 lowercase hex>`.
6. `confidence` is present only and always for `inferred`.
7. Unknown actor roles, fields, relation types, and top-level fields are
   rejected. Extensions use explicitly namespaced keys.

Validators MUST fail closed on structural errors. They SHOULD return all
independent validation errors in a single pass. They MUST NOT repair input
without recording a migration or transformation step.

## 9. EACP 1.2 CSV migration

The migration input is the 13-column projection:

```text
source_type,source_id,source_ts,observed_ts,actor,service,intent,policy,
action,outcome,source_pointer,correlation_id,content_hash
```

Column order MAY vary, but the header set MUST match exactly. Each row maps as
follows:

| EACP 1.2 | EACP 1.3 |
| --- | --- |
| `source_type`, `source_id`, timestamps, intent, policy, action, outcome, pointer | Preserved without rewriting. |
| `actor` | `actors.execution_principal`, type `legacy_opaque`, in the caller-supplied migration scope. |
| `service` | `service.id`, type `legacy_opaque`, in the caller-supplied migration scope. |
| non-empty `correlation_id` | `operational_correlation` link using the same value and scope, with `evidence_method: explicit`. |
| empty `correlation_id` | No link; resolution therefore abstains as `missing`. |
| `content_hash` | Preserved verbatim in `extensions["org.eacp/legacy_v1_2"]`; it is not relabeled a source digest. |

Migration requires an explicit scope type and scope identifier. This prevents
identical unscoped strings from unrelated datasets being silently merged. The
extension retains the original `actor`, `service`, `correlation_id`, and
`content_hash`, making the transform auditable and lossless for all 13 source
values.

The migration is backward-compatible at the data boundary, not a claim that
1.2 supplied the new role, service-type, or link-method semantics. Consumers
requiring those semantics SHOULD enrich records from original source evidence
and issue new records rather than editing migrated evidence in place.

## 10. Reference commands

Validate one record, a JSON array, or JSON Lines:

```sh
python3 spec/tools/eacp_profile.py validate spec/examples/valid-record-v1.3.json
```

Migrate the legacy CSV without guessing a global scope:

```sh
python3 spec/tools/eacp_profile.py migrate legacy.csv migrated.jsonl \
  --scope-type legacy_dataset \
  --scope-id urn:eacp:dataset:example-2026-09
```

Resolve one seed record by exact operational correlation:

```sh
python3 spec/tools/eacp_profile.py resolve migrated.jsonl \
  --source-type kubernetes.audit \
  --source-id kubernetes-audit://example \
  --link-type operational_correlation
```

The tool writes machine-readable JSON diagnostics to standard output and uses
a non-zero exit status for invalid input or an unresolved request. It never
modifies its input.

## 11. Versioning

`eacp.profile/1.3` identifies this profile family. New standard relation types
or actor roles require a later profile version because this profile rejects
unknown fields and enum values; experimental relation names can use
`type: custom` plus a namespaced `custom_type`. Producers SHOULD retain the
schema URL used to validate records in collection-level metadata; the
`profile` value remains the runtime discriminator.
