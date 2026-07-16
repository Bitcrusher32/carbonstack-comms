# Gate F F5 Basic Local Trust Posture

Status: accepted implementation document
Scope: v0.7.x Gate F F5

## Summary

Gate F F5 adds a basic local trust candidate posture for dev/pre-alpha operation.

The posture is intentionally local and manual.

It is not verified identity.

It is not full trust promotion.

It is not secure enrollment.

It is not cryptographic binding across Cypher, Comms, and OpenMLS identities.

## Commands

basic-local-trust-posture-dev prints a report over the observed local identity domains.

basic-local-trust-accept-dev records an explicit local manual candidate acceptance event.

The acceptance command requires explicit operator confirmation through accept-candidate and a reason.

## Identity domains

F5 distinguishes:

- Cypher account/device identity as coordination and routing identity only.
- Comms local trust/candidate fingerprint as local operator policy evidence only.
- OpenMLS sidecar device label and KeyPackage reference as cryptographic group material, not real-world identity.
- Relay Space membership as routing membership only.

## Rules

Relay membership does not promote trust.

Successful Welcome or MLS join does not promote trust.

Local acceptance does not verify identity.

Local acceptance does not bind identity domains cryptographically.

Changed or missing evidence must stay loud and refusal-oriented.

## Nonclaims

F5 is not verified identity, not full trust promotion, not secure enrollment, not server-hostile identity replacement proof, not real-world person verification, not production E2EE, not package/runtime candidate validation, and not release readiness.

