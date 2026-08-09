# H0 Local Trust Binding v1 Contract

Schema marker: `carbonstack-comms-local-trust-binding-v1-contract`

## Purpose

H0 turns existing OpenMLS, Cypher, provider, trust-candidate, and Relay Space fixtures into a code-bearing local trust-binding behavior in `carbonstack-comms`.

This is a dev/pre-alpha security behavior sprint. It is not production identity and not secure enrollment.

## Primary mutation repo

```text
PRIMARY_MUTATION_REPO=carbonstack-comms
```

`carbonstack-cypher` is not mutated in H0 unless a later implementation proves a relay-side field or endpoint is strictly required. `carbonstack` registry/profile mutation is deferred until the Comms behavior exists.

## Behavior implemented

H0 local trust binding v1 records composite local evidence across:

- subject label;
- Cypher account ID;
- Cypher device ID;
- Relay Space ID;
- OpenMLS credential fingerprint;
- OpenMLS signer fingerprint;
- KeyPackage fingerprint;
- KeyPackage lineage;
- first observed time;
- last observed time;
- candidate source.

The binding may be promoted only by explicit operator event and verification method.

## States

```text
candidate_observed
promoted_local_trust
changed_signer_warning
changed_device_warning
changed_key_lineage_warning
demoted
revoked
```

## Mandatory refusal boundaries

```text
Relay membership does not become trust.
MLS join does not become trust.
Provider observation does not become trust.
KeyPackage publication does not become trust.
Label similarity/spoofing does not become verified identity.
Changed signer/device/key lineage is loud.
Promotion requires explicit operator event.
Demotion/revocation require explicit events.
```

## Nonclaims

H0 local trust binding v1 is:

- not production verified identity;
- not secure enrollment;
- not hostile-server identity replacement proof;
- not hardware-backed identity;
- not production E2EE readiness;
- not metadata privacy proof;
- not production vault;
- not secret-bearing backup/restore;
- not external audit;
- not external pen-test completion.

## Done condition

```text
carbonstack-comms mutated
internal/trust/local_trust_binding_v1.go exists
internal/trust/local_trust_binding_v1_test.go exists
go test ./... passes in carbonstack-comms
Relay membership / MLS join / provider observation / KeyPackage publication cannot autopromote
changed signer/device/key lineage produces loud warning state
promotion/demotion/revocation require explicit events
carbonstack registry not mutated
carbonstack-cypher not mutated
```
