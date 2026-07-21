package trust

import (
	"errors"
	"strings"
	"time"
)

const GateCLocalTrustCandidateSchema = "carbonstack-local-trust-candidate/v0"

const (
	GateCTrustStateCandidateObserved      = "candidate_observed"
	GateCTrustStateOperatorReviewRequired = "operator_review_required"
	GateCTrustStatePromotedLocalTrust     = "promoted_local_trust"
	GateCTrustStateChangedLineageWarning  = "changed_lineage_warning"
	GateCTrustStateDemoted                = "demoted"
	GateCTrustStateRevoked                = "revoked"
	GateCTrustStateUnknownOrUntrusted     = "unknown_or_untrusted"
)

type GateCLocalTrustEvidence struct {
	SubjectLabel                 string
	CypherAccountID              string
	CypherDeviceID               string
	RelaySpaceID                 string
	RelaySpaceContext            string
	OpenMLSSignerFingerprint     string
	OpenMLSCredentialFingerprint string
	KeyPackageFingerprint        string
	KeyPackageLineage            string
	VerificationMethod           string
}

type GateCLocalTrustCandidate struct {
	SchemaVersion                string   `json:"schema_version"`
	CandidateID                  string   `json:"candidate_id"`
	SubjectLabel                 string   `json:"subject_label"`
	CypherAccountID              string   `json:"cypher_account_id"`
	CypherDeviceID               string   `json:"cypher_device_id"`
	RelaySpaceID                 string   `json:"relay_space_id"`
	RelaySpaceContext            string   `json:"relay_space_context"`
	OpenMLSSignerFingerprint     string   `json:"openmls_signer_fingerprint"`
	OpenMLSCredentialFingerprint string   `json:"openmls_credential_fingerprint"`
	KeyPackageFingerprint        string   `json:"keypackage_fingerprint"`
	KeyPackageLineage            string   `json:"keypackage_lineage"`
	FirstObservedAt              string   `json:"first_observed_at"`
	LastObservedAt               string   `json:"last_observed_at"`
	VerificationMethod           string   `json:"verification_method"`
	OperatorReviewEventID        string   `json:"operator_review_event_id"`
	OperatorPromotionEventID     string   `json:"operator_promotion_event_id"`
	TrustLevel                   string   `json:"trust_level"`
	TrustState                   string   `json:"trust_state"`
	ChangedLineageWarnings       []string `json:"changed_lineage_warnings"`
	DemotionOrRevocationEventID  string   `json:"demotion_or_revocation_event_id"`
	Nonclaims                    []string `json:"nonclaims"`
}

func NewGateCLocalTrustCandidate(candidateID string, evidence GateCLocalTrustEvidence, observedAt time.Time) GateCLocalTrustCandidate {
	normalized := normalizeGateCEvidence(evidence)
	return GateCLocalTrustCandidate{
		SchemaVersion:                GateCLocalTrustCandidateSchema,
		CandidateID:                  strings.TrimSpace(candidateID),
		SubjectLabel:                 normalized.SubjectLabel,
		CypherAccountID:              normalized.CypherAccountID,
		CypherDeviceID:               normalized.CypherDeviceID,
		RelaySpaceID:                 normalized.RelaySpaceID,
		RelaySpaceContext:            normalized.RelaySpaceContext,
		OpenMLSSignerFingerprint:     normalized.OpenMLSSignerFingerprint,
		OpenMLSCredentialFingerprint: normalized.OpenMLSCredentialFingerprint,
		KeyPackageFingerprint:        normalized.KeyPackageFingerprint,
		KeyPackageLineage:            normalized.KeyPackageLineage,
		FirstObservedAt:              observedAt.UTC().Format(time.RFC3339),
		LastObservedAt:               observedAt.UTC().Format(time.RFC3339),
		VerificationMethod:           normalized.VerificationMethod,
		TrustLevel:                   "candidate",
		TrustState:                   GateCTrustStateCandidateObserved,
		ChangedLineageWarnings:       []string{},
		Nonclaims:                    GateCLocalTrustCandidateNonclaims(),
	}
}

func MarkGateCLocalTrustCandidateReview(candidate GateCLocalTrustCandidate, reviewEventID string, reviewedAt time.Time) (GateCLocalTrustCandidate, error) {
	reviewEventID = strings.TrimSpace(reviewEventID)
	if reviewEventID == "" {
		return candidate, errors.New("operator review event ID is required")
	}
	candidate.OperatorReviewEventID = reviewEventID
	candidate.TrustState = GateCTrustStateOperatorReviewRequired
	candidate.LastObservedAt = reviewedAt.UTC().Format(time.RFC3339)
	return candidate, nil
}

func PromoteGateCLocalTrustCandidate(candidate GateCLocalTrustCandidate, promotionEventID string, verificationMethod string, promotedAt time.Time) (GateCLocalTrustCandidate, error) {
	promotionEventID = strings.TrimSpace(promotionEventID)
	verificationMethod = strings.TrimSpace(verificationMethod)
	if promotionEventID == "" {
		return candidate, errors.New("explicit operator promotion event ID is required")
	}
	if verificationMethod == "" {
		return candidate, errors.New("verification method is required for local trust promotion")
	}
	if len(candidate.ChangedLineageWarnings) > 0 {
		return candidate, errors.New("cannot promote candidate while changed lineage warnings are present")
	}
	candidate.OperatorPromotionEventID = promotionEventID
	candidate.VerificationMethod = verificationMethod
	candidate.TrustLevel = "local_manual_trust"
	candidate.TrustState = GateCTrustStatePromotedLocalTrust
	candidate.LastObservedAt = promotedAt.UTC().Format(time.RFC3339)
	candidate.Nonclaims = GateCLocalTrustCandidateNonclaims()
	return candidate, nil
}

func RevokeGateCLocalTrustCandidate(candidate GateCLocalTrustCandidate, eventID string, revokedAt time.Time) (GateCLocalTrustCandidate, error) {
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return candidate, errors.New("demotion or revocation event ID is required")
	}
	candidate.DemotionOrRevocationEventID = eventID
	candidate.TrustLevel = "untrusted"
	candidate.TrustState = GateCTrustStateRevoked
	candidate.LastObservedAt = revokedAt.UTC().Format(time.RFC3339)
	return candidate, nil
}

func GateCLocalTrustChangedLineageWarnings(candidate GateCLocalTrustCandidate, evidence GateCLocalTrustEvidence) []string {
	normalized := normalizeGateCEvidence(evidence)
	var warnings []string
	if candidate.CypherDeviceID != "" && normalized.CypherDeviceID != "" && candidate.CypherDeviceID != normalized.CypherDeviceID {
		warnings = append(warnings, "changed_cypher_device_id")
	}
	if candidate.OpenMLSSignerFingerprint != "" && normalized.OpenMLSSignerFingerprint != "" && candidate.OpenMLSSignerFingerprint != normalized.OpenMLSSignerFingerprint {
		warnings = append(warnings, "changed_openmls_signer_fingerprint")
	}
	if candidate.OpenMLSCredentialFingerprint != "" && normalized.OpenMLSCredentialFingerprint != "" && candidate.OpenMLSCredentialFingerprint != normalized.OpenMLSCredentialFingerprint {
		warnings = append(warnings, "changed_openmls_credential_fingerprint")
	}
	if candidate.KeyPackageFingerprint != "" && normalized.KeyPackageFingerprint != "" && candidate.KeyPackageFingerprint != normalized.KeyPackageFingerprint {
		warnings = append(warnings, "changed_keypackage_fingerprint")
	}
	if candidate.KeyPackageLineage != "" && normalized.KeyPackageLineage != "" && candidate.KeyPackageLineage != normalized.KeyPackageLineage {
		warnings = append(warnings, "changed_keypackage_lineage")
	}
	return warnings
}

func ApplyGateCLocalTrustChangedLineage(candidate GateCLocalTrustCandidate, evidence GateCLocalTrustEvidence, observedAt time.Time) GateCLocalTrustCandidate {
	warnings := GateCLocalTrustChangedLineageWarnings(candidate, evidence)
	candidate.ChangedLineageWarnings = warnings
	candidate.LastObservedAt = observedAt.UTC().Format(time.RFC3339)
	if len(warnings) > 0 {
		candidate.TrustState = GateCTrustStateChangedLineageWarning
	}
	candidate.Nonclaims = GateCLocalTrustCandidateNonclaims()
	return candidate
}

func GateCLocalTrustCandidateNonclaims() []string {
	return []string{
		"not production verified identity",
		"not secure enrollment",
		"not hardware-backed identity",
		"not real-world person verification",
		"not automatic trust promotion",
		"not hostile-server identity replacement proof",
		"not trust from Relay membership",
		"not trust from MLS join",
		"not trust from provider observation",
		"not cryptographic binding across Cypher, Comms, and OpenMLS identities",
	}
}

func GateCLocalTrustClaims() map[string]bool {
	return map[string]bool{
		"production_verified_identity":                  false,
		"secure_enrollment":                             false,
		"hardware_backed_identity":                      false,
		"real_world_person_verification":                false,
		"automatic_trust_promotion":                     false,
		"hostile_server_identity_replacement_proof":     false,
		"relay_membership_trust_authority":              false,
		"mls_join_trust_authority":                      false,
		"provider_observation_trust_authority":          false,
		"cryptographic_identity_binding_across_domains": false,
	}
}

func GateCLocalTrustRules() []string {
	return []string{
		"Relay membership is not trust",
		"MLS join is not trust",
		"Provider observation is not trust",
		"candidate state is not promoted without explicit operator action",
		"changed signer/device/key lineage is loud",
		"unknown or changed trust state can be refused for safety-sensitive workflows",
		"dev overrides, if any, are explicit, logged, non-default, and dev/pre-alpha scoped",
	}
}

func normalizeGateCEvidence(e GateCLocalTrustEvidence) GateCLocalTrustEvidence {
	return GateCLocalTrustEvidence{
		SubjectLabel:                 strings.TrimSpace(e.SubjectLabel),
		CypherAccountID:              strings.TrimSpace(e.CypherAccountID),
		CypherDeviceID:               strings.TrimSpace(e.CypherDeviceID),
		RelaySpaceID:                 strings.TrimSpace(e.RelaySpaceID),
		RelaySpaceContext:            strings.TrimSpace(e.RelaySpaceContext),
		OpenMLSSignerFingerprint:     strings.TrimSpace(e.OpenMLSSignerFingerprint),
		OpenMLSCredentialFingerprint: strings.TrimSpace(e.OpenMLSCredentialFingerprint),
		KeyPackageFingerprint:        strings.TrimSpace(e.KeyPackageFingerprint),
		KeyPackageLineage:            strings.TrimSpace(e.KeyPackageLineage),
		VerificationMethod:           strings.TrimSpace(e.VerificationMethod),
	}
}
