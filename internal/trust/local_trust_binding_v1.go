package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const LocalTrustBindingV1Schema = "carbonstack-comms-local-trust-binding-v1"

type LocalTrustBindingState string

const (
	LocalTrustBindingCandidateObserved    LocalTrustBindingState = "candidate_observed"
	LocalTrustBindingPromotedLocalTrust   LocalTrustBindingState = "promoted_local_trust"
	LocalTrustBindingChangedSignerWarning LocalTrustBindingState = "changed_signer_warning"
	LocalTrustBindingChangedDeviceWarning LocalTrustBindingState = "changed_device_warning"
	LocalTrustBindingChangedKeyWarning    LocalTrustBindingState = "changed_key_lineage_warning"
	LocalTrustBindingDemoted              LocalTrustBindingState = "demoted"
	LocalTrustBindingRevoked              LocalTrustBindingState = "revoked"
)

type LocalTrustBindingEvidenceV1 struct {
	SubjectLabel                 string `json:"subject_label"`
	CypherAccountID              string `json:"cypher_account_id"`
	CypherDeviceID               string `json:"cypher_device_id"`
	RelaySpaceID                 string `json:"relay_space_id"`
	OpenMLSCredentialFingerprint string `json:"openmls_credential_fingerprint"`
	OpenMLSSignerFingerprint     string `json:"openmls_signer_fingerprint"`
	KeyPackageFingerprint        string `json:"keypackage_fingerprint"`
	KeyPackageLineage            string `json:"keypackage_lineage"`
	FirstObservedAt              string `json:"first_observed_at"`
	LastObservedAt               string `json:"last_observed_at"`
	CandidateSource              string `json:"candidate_source"`
	ProviderObservationEventID   string `json:"provider_observation_event_id,omitempty"`
	RelayMembershipEventID       string `json:"relay_membership_event_id,omitempty"`
	MLSJoinEventID               string `json:"mls_join_event_id,omitempty"`
}

type LocalTrustBindingV1 struct {
	SchemaVersion            string                      `json:"schema_version"`
	State                    LocalTrustBindingState      `json:"state"`
	Evidence                 LocalTrustBindingEvidenceV1 `json:"evidence"`
	BindingFingerprint       string                      `json:"binding_fingerprint"`
	OperatorPromotionEventID string                      `json:"operator_promotion_event_id,omitempty"`
	VerificationMethod       string                      `json:"verification_method,omitempty"`
	DemotionOrRevocationID   string                      `json:"demotion_or_revocation_event_id,omitempty"`
	Warnings                 []string                    `json:"warnings,omitempty"`
	Nonclaims                []string                    `json:"nonclaims"`
}

type LocalTrustBindingChangeV1 struct {
	NewCypherAccountID              string
	NewCypherDeviceID               string
	NewRelaySpaceID                 string
	NewOpenMLSCredentialFingerprint string
	NewOpenMLSSignerFingerprint     string
	NewKeyPackageFingerprint        string
	NewKeyPackageLineage            string
}

func NewLocalTrustBindingCandidateV1(evidence LocalTrustBindingEvidenceV1) (LocalTrustBindingV1, error) {
	normalized, err := normalizeLocalTrustBindingEvidenceV1(evidence)
	if err != nil {
		return LocalTrustBindingV1{}, err
	}
	fp := fingerprintLocalTrustBindingEvidenceV1(normalized)
	return LocalTrustBindingV1{
		SchemaVersion:      LocalTrustBindingV1Schema,
		State:              LocalTrustBindingCandidateObserved,
		Evidence:           normalized,
		BindingFingerprint: fp,
		Warnings: []string{
			"candidate evidence only",
			"relay membership is not trust",
			"MLS join is not trust",
			"provider observation is not trust",
			"KeyPackage publication is not trust",
		},
		Nonclaims: localTrustBindingV1Nonclaims(),
	}, nil
}

func PromoteLocalTrustBindingV1(candidate LocalTrustBindingV1, operatorPromotionEventID, verificationMethod string) (LocalTrustBindingV1, error) {
	if candidate.SchemaVersion != LocalTrustBindingV1Schema {
		return LocalTrustBindingV1{}, errors.New("unsupported local trust binding schema")
	}
	if candidate.State != LocalTrustBindingCandidateObserved {
		return LocalTrustBindingV1{}, fmt.Errorf("can only promote candidate_observed binding, got %s", candidate.State)
	}
	if strings.TrimSpace(operatorPromotionEventID) == "" {
		return LocalTrustBindingV1{}, errors.New("operator promotion event ID is required")
	}
	if strings.TrimSpace(verificationMethod) == "" {
		return LocalTrustBindingV1{}, errors.New("verification method is required")
	}
	out := candidate
	out.State = LocalTrustBindingPromotedLocalTrust
	out.OperatorPromotionEventID = strings.TrimSpace(operatorPromotionEventID)
	out.VerificationMethod = strings.TrimSpace(verificationMethod)
	out.Warnings = appendStableUnique(out.Warnings,
		[]string{"promoted local trust is local/manual trust only", "not verified identity", "not secure enrollment"},
	)
	out.Nonclaims = localTrustBindingV1Nonclaims()
	return out, nil
}

func ApplyLocalTrustBindingChangeV1(binding LocalTrustBindingV1, change LocalTrustBindingChangeV1) LocalTrustBindingV1 {
	out := binding
	warnings := append([]string{}, binding.Warnings...)

	if changed(change.NewOpenMLSSignerFingerprint, binding.Evidence.OpenMLSSignerFingerprint) {
		out.State = LocalTrustBindingChangedSignerWarning
		warnings = append(warnings, "changed signer/device/key lineage is loud", "changed OpenMLS signer fingerprint")
	}
	if changed(change.NewCypherDeviceID, binding.Evidence.CypherDeviceID) {
		if out.State == binding.State {
			out.State = LocalTrustBindingChangedDeviceWarning
		}
		warnings = append(warnings, "changed signer/device/key lineage is loud", "changed Cypher device ID")
	}
	if changed(change.NewKeyPackageFingerprint, binding.Evidence.KeyPackageFingerprint) || changed(change.NewKeyPackageLineage, binding.Evidence.KeyPackageLineage) || changed(change.NewOpenMLSCredentialFingerprint, binding.Evidence.OpenMLSCredentialFingerprint) {
		if out.State == binding.State {
			out.State = LocalTrustBindingChangedKeyWarning
		}
		warnings = append(warnings, "changed signer/device/key lineage is loud", "changed key lineage or OpenMLS credential")
	}
	if changed(change.NewCypherAccountID, binding.Evidence.CypherAccountID) {
		if out.State == binding.State {
			out.State = LocalTrustBindingChangedDeviceWarning
		}
		warnings = append(warnings, "changed Cypher account ID")
	}
	if changed(change.NewRelaySpaceID, binding.Evidence.RelaySpaceID) {
		warnings = append(warnings, "Relay Space change is routing context change, not trust promotion")
	}

	out.Warnings = appendStableUnique(warnings)
	out.Nonclaims = localTrustBindingV1Nonclaims()
	return out
}

func DemoteLocalTrustBindingV1(binding LocalTrustBindingV1, eventID string) (LocalTrustBindingV1, error) {
	if strings.TrimSpace(eventID) == "" {
		return LocalTrustBindingV1{}, errors.New("demotion event ID is required")
	}
	out := binding
	out.State = LocalTrustBindingDemoted
	out.DemotionOrRevocationID = strings.TrimSpace(eventID)
	out.Warnings = appendStableUnique(out.Warnings, []string{"local trust binding demoted"})
	out.Nonclaims = localTrustBindingV1Nonclaims()
	return out, nil
}

func RevokeLocalTrustBindingV1(binding LocalTrustBindingV1, eventID string) (LocalTrustBindingV1, error) {
	if strings.TrimSpace(eventID) == "" {
		return LocalTrustBindingV1{}, errors.New("revocation event ID is required")
	}
	out := binding
	out.State = LocalTrustBindingRevoked
	out.DemotionOrRevocationID = strings.TrimSpace(eventID)
	out.Warnings = appendStableUnique(out.Warnings, []string{"local trust binding revoked"})
	out.Nonclaims = localTrustBindingV1Nonclaims()
	return out, nil
}

func RelayMembershipObservationV1(evidence LocalTrustBindingEvidenceV1) (LocalTrustBindingV1, error) {
	out, err := NewLocalTrustBindingCandidateV1(evidence)
	if err != nil {
		return LocalTrustBindingV1{}, err
	}
	out.Warnings = appendStableUnique(out.Warnings, []string{"Relay membership observation remains candidate evidence only"})
	return out, nil
}

func MLSJoinObservationV1(evidence LocalTrustBindingEvidenceV1) (LocalTrustBindingV1, error) {
	out, err := NewLocalTrustBindingCandidateV1(evidence)
	if err != nil {
		return LocalTrustBindingV1{}, err
	}
	out.Warnings = appendStableUnique(out.Warnings, []string{"MLS join observation remains candidate evidence only"})
	return out, nil
}

func ProviderObservationV1(evidence LocalTrustBindingEvidenceV1) (LocalTrustBindingV1, error) {
	out, err := NewLocalTrustBindingCandidateV1(evidence)
	if err != nil {
		return LocalTrustBindingV1{}, err
	}
	out.Warnings = appendStableUnique(out.Warnings, []string{"provider observation remains candidate evidence only"})
	return out, nil
}

func KeyPackagePublicationObservationV1(evidence LocalTrustBindingEvidenceV1) (LocalTrustBindingV1, error) {
	out, err := NewLocalTrustBindingCandidateV1(evidence)
	if err != nil {
		return LocalTrustBindingV1{}, err
	}
	out.Warnings = appendStableUnique(out.Warnings, []string{"KeyPackage publication remains candidate evidence only"})
	return out, nil
}

func normalizeLocalTrustBindingEvidenceV1(e LocalTrustBindingEvidenceV1) (LocalTrustBindingEvidenceV1, error) {
	e.SubjectLabel = strings.TrimSpace(e.SubjectLabel)
	e.CypherAccountID = strings.TrimSpace(e.CypherAccountID)
	e.CypherDeviceID = strings.TrimSpace(e.CypherDeviceID)
	e.RelaySpaceID = strings.TrimSpace(e.RelaySpaceID)
	e.OpenMLSCredentialFingerprint = strings.TrimSpace(e.OpenMLSCredentialFingerprint)
	e.OpenMLSSignerFingerprint = strings.TrimSpace(e.OpenMLSSignerFingerprint)
	e.KeyPackageFingerprint = strings.TrimSpace(e.KeyPackageFingerprint)
	e.KeyPackageLineage = strings.TrimSpace(e.KeyPackageLineage)
	e.FirstObservedAt = strings.TrimSpace(e.FirstObservedAt)
	e.LastObservedAt = strings.TrimSpace(e.LastObservedAt)
	e.CandidateSource = strings.TrimSpace(e.CandidateSource)
	e.ProviderObservationEventID = strings.TrimSpace(e.ProviderObservationEventID)
	e.RelayMembershipEventID = strings.TrimSpace(e.RelayMembershipEventID)
	e.MLSJoinEventID = strings.TrimSpace(e.MLSJoinEventID)

	required := map[string]string{
		"subject_label":                  e.SubjectLabel,
		"cypher_account_id":              e.CypherAccountID,
		"cypher_device_id":               e.CypherDeviceID,
		"relay_space_id":                 e.RelaySpaceID,
		"openmls_credential_fingerprint": e.OpenMLSCredentialFingerprint,
		"openmls_signer_fingerprint":     e.OpenMLSSignerFingerprint,
		"keypackage_fingerprint":         e.KeyPackageFingerprint,
		"keypackage_lineage":             e.KeyPackageLineage,
		"first_observed_at":              e.FirstObservedAt,
		"last_observed_at":               e.LastObservedAt,
		"candidate_source":               e.CandidateSource,
	}
	keys := make([]string, 0, len(required))
	for k := range required {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if required[k] == "" {
			return LocalTrustBindingEvidenceV1{}, fmt.Errorf("%s is required", k)
		}
	}
	return e, nil
}

func fingerprintLocalTrustBindingEvidenceV1(e LocalTrustBindingEvidenceV1) string {
	parts := []string{
		e.SubjectLabel,
		e.CypherAccountID,
		e.CypherDeviceID,
		e.RelaySpaceID,
		e.OpenMLSCredentialFingerprint,
		e.OpenMLSSignerFingerprint,
		e.KeyPackageFingerprint,
		e.KeyPackageLineage,
		e.CandidateSource,
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(h[:])
}

func localTrustBindingV1Nonclaims() []string {
	return []string{
		"not production verified identity",
		"not secure enrollment",
		"not hostile-server identity replacement proof",
		"not hardware-backed identity",
		"not production E2EE readiness",
		"not metadata privacy proof",
		"not production vault",
		"not secret-bearing backup/restore",
		"not external audit",
		"not external pen-test completion",
	}
}

func changed(next, current string) bool {
	next = strings.TrimSpace(next)
	current = strings.TrimSpace(current)
	return next != "" && current != "" && next != current
}

func appendStableUnique(groups ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, group := range groups {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
