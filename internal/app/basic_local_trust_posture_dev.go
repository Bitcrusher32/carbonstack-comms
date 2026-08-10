package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var basicLocalTrustPostureSlugRE = regexp.MustCompile("[^a-z0-9._-]+")

const basicLocalTrustPostureSchema = "carbonstack-basic-local-trust-posture/v0"
const basicLocalTrustAcceptanceEventSchema = "carbonstack-basic-local-trust-acceptance-event/v0"

type basicLocalTrustInput struct {
	StatePath          string
	SubjectLabel       string
	CypherAccountID    string
	CypherDeviceID     string
	CommsFingerprint   string
	OpenMLSDeviceLabel string
	OpenMLSKeyPackage  string
	RelaySpaceID       string
	Reason             string
	SourceReport       string
	EventRoot          string
	ReportPath         string
	AcceptCandidate    bool
}

func cmdBasicLocalTrustPostureDev(args []string) error {
	fs := flag.NewFlagSet("basic-local-trust-posture-dev", flag.ContinueOnError)
	input := basicLocalTrustInput{}
	fs.StringVar(&input.StatePath, "state", ".carbonstack-comms-state", "local Comms state root used only for default event-root derivation")
	fs.StringVar(&input.SubjectLabel, "subject-label", "", "local human/operator label for the candidate subject")
	fs.StringVar(&input.CypherAccountID, "cypher-account", "", "observed Cypher account identifier")
	fs.StringVar(&input.CypherDeviceID, "cypher-device", "", "observed Cypher device identifier")
	fs.StringVar(&input.CommsFingerprint, "comms-fingerprint", "", "observed local Comms trust/candidate fingerprint")
	fs.StringVar(&input.OpenMLSDeviceLabel, "openmls-device-label", "", "observed OpenMLS sidecar device label")
	fs.StringVar(&input.OpenMLSKeyPackage, "openmls-keypackage-ref", "", "observed OpenMLS KeyPackage reference or related material")
	fs.StringVar(&input.RelaySpaceID, "relay-space", "", "observed Relay Space routing context")
	fs.StringVar(&input.ReportPath, "report", "", "optional report output path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report := buildBasicLocalTrustPostureReport(input, time.Now().UTC())
	if input.ReportPath != "" {
		if err := writeBasicLocalTrustJSONAtomic(input.ReportPath, report); err != nil {
			return err
		}
	}
	return printBasicLocalTrustJSON(report)
}

func cmdBasicLocalTrustAcceptDev(args []string) error {
	fs := flag.NewFlagSet("basic-local-trust-accept-dev", flag.ContinueOnError)
	input := basicLocalTrustInput{}
	fs.StringVar(&input.StatePath, "state", ".carbonstack-comms-state", "local Comms state root used only for default event-root derivation")
	fs.StringVar(&input.EventRoot, "event-root", "", "local event root for manual local trust acceptance evidence")
	fs.StringVar(&input.SubjectLabel, "subject-label", "", "local human/operator label for the candidate subject")
	fs.StringVar(&input.CypherAccountID, "cypher-account", "", "observed Cypher account identifier")
	fs.StringVar(&input.CypherDeviceID, "cypher-device", "", "observed Cypher device identifier")
	fs.StringVar(&input.CommsFingerprint, "comms-fingerprint", "", "observed local Comms trust/candidate fingerprint")
	fs.StringVar(&input.OpenMLSDeviceLabel, "openmls-device-label", "", "observed OpenMLS sidecar device label")
	fs.StringVar(&input.OpenMLSKeyPackage, "openmls-keypackage-ref", "", "observed OpenMLS KeyPackage reference or related material")
	fs.StringVar(&input.RelaySpaceID, "relay-space", "", "observed Relay Space routing context")
	fs.StringVar(&input.Reason, "reason", "", "operator reason for explicit local acceptance")
	fs.StringVar(&input.SourceReport, "source-report", "", "optional posture/source report path")
	fs.BoolVar(&input.AcceptCandidate, "accept-candidate", false, "required explicit confirmation for local manual candidate acceptance")
	if err := fs.Parse(args); err != nil {
		return err
	}

	event, eventPath, err := buildAndPersistBasicLocalTrustAcceptance(input, time.Now().UTC())
	if err != nil {
		return err
	}
	out := map[string]any{
		"schema_version": "carbonstack-basic-local-trust-acceptance-command-result/v0",
		"event_path":     eventPath,
		"event":          event,
	}
	return printBasicLocalTrustJSON(out)
}

func buildBasicLocalTrustPostureReport(input basicLocalTrustInput, now time.Time) map[string]any {
	normalized := normalizeBasicLocalTrustInput(input)
	missing := basicLocalTrustMissingForAcceptance(normalized)
	ready := len(missing) == 0
	openMLSPresent := normalized.OpenMLSDeviceLabel != "" || normalized.OpenMLSKeyPackage != ""

	return map[string]any{
		"schema_version":                    basicLocalTrustPostureSchema,
		"created_at":                        now.Format(time.RFC3339),
		"status":                            basicLocalTrustStatus(ready),
		"ready_for_manual_local_acceptance": ready,
		"missing_required_for_manual_local_acceptance": missing,
		"identity_domains": map[string]any{
			"cypher_account_device": map[string]any{
				"present":            normalized.CypherAccountID != "" && normalized.CypherDeviceID != "",
				"account_id_present": normalized.CypherAccountID != "",
				"device_id_present":  normalized.CypherDeviceID != "",
				"meaning":            "coordination and routing identity only",
			},
			"comms_local_trust_candidate": map[string]any{
				"present":             normalized.CommsFingerprint != "",
				"fingerprint_present": normalized.CommsFingerprint != "",
				"meaning":             "local operator policy and evidence only",
			},
			"openmls_signer_keypackage": map[string]any{
				"present":                openMLSPresent,
				"device_label_present":   normalized.OpenMLSDeviceLabel != "",
				"keypackage_ref_present": normalized.OpenMLSKeyPackage != "",
				"meaning":                "group cryptographic material and sidecar identity surface, not a verified real-world identity",
			},
			"relay_membership": map[string]any{
				"present": normalized.RelaySpaceID != "",
				"meaning": "routing and membership coordination only, never trust promotion",
			},
		},
		"observed": map[string]any{
			"subject_label":          normalized.SubjectLabel,
			"cypher_account":         normalized.CypherAccountID,
			"cypher_device":          normalized.CypherDeviceID,
			"comms_fingerprint":      normalized.CommsFingerprint,
			"openmls_device_label":   normalized.OpenMLSDeviceLabel,
			"openmls_keypackage_ref": normalized.OpenMLSKeyPackage,
			"relay_space":            normalized.RelaySpaceID,
		},
		"claims":    basicLocalTrustNonclaimMap(),
		"nonclaims": basicLocalTrustNonclaims(),
		"rules": []string{
			"manual local acceptance requires explicit operator action",
			"Relay membership is not trust promotion",
			"successful Welcome or MLS join is not trust promotion",
			"local acceptance is not verified identity",
			"local acceptance is not secure enrollment",
			"identity domains are correlated by operator evidence but not cryptographically unified",
			"changed or missing material must stay loud and refusal-oriented",
		},
	}
}

func buildAndPersistBasicLocalTrustAcceptance(input basicLocalTrustInput, now time.Time) (map[string]any, string, error) {
	normalized := normalizeBasicLocalTrustInput(input)
	if !normalized.AcceptCandidate {
		return nil, "", errors.New("basic local trust acceptance requires --accept-candidate")
	}
	if strings.TrimSpace(normalized.Reason) == "" {
		return nil, "", errors.New("basic local trust acceptance requires --reason")
	}
	missing := basicLocalTrustMissingForAcceptance(normalized)
	if len(missing) > 0 {
		return nil, "", fmt.Errorf("basic local trust acceptance missing required evidence: %s", strings.Join(missing, ", "))
	}

	eventRoot := normalized.EventRoot
	if eventRoot == "" {
		state := normalized.StatePath
		if state == "" {
			state = ".carbonstack-comms-state"
		}
		eventRoot = filepath.Join(state, "basic-local-trust-events")
	}
	eventID := basicLocalTrustEventID(normalized, now)
	event := map[string]any{
		"schema_version": basicLocalTrustAcceptanceEventSchema,
		"event_id":       eventID,
		"event_type":     "manual_local_trust_candidate_acceptance",
		"created_at":     now.Format(time.RFC3339),
		"subject_label":  normalized.SubjectLabel,
		"reason":         normalized.Reason,
		"source_report":  normalized.SourceReport,
		"identity_domains": map[string]any{
			"cypher_account_device": map[string]any{
				"account_id": normalized.CypherAccountID,
				"device_id":  normalized.CypherDeviceID,
				"meaning":    "coordination and routing identity only",
			},
			"comms_local_trust_candidate": map[string]any{
				"fingerprint": normalized.CommsFingerprint,
				"meaning":     "local operator policy and evidence only",
			},
			"openmls_signer_keypackage": map[string]any{
				"device_label":   normalized.OpenMLSDeviceLabel,
				"keypackage_ref": normalized.OpenMLSKeyPackage,
				"present":        normalized.OpenMLSDeviceLabel != "" || normalized.OpenMLSKeyPackage != "",
				"meaning":        "group cryptographic material and sidecar identity surface, not verified identity",
			},
			"relay_membership": map[string]any{
				"relay_space": normalized.RelaySpaceID,
				"meaning":     "routing and membership coordination only, not trust promotion",
			},
		},
		"claims":    basicLocalTrustNonclaimMap(),
		"nonclaims": basicLocalTrustNonclaims(),
		"rules": []string{
			"this event records local manual candidate acceptance only",
			"this event does not verify a person or device identity",
			"this event does not cryptographically bind Cypher, Comms, and OpenMLS identities",
			"this event does not allow automatic trust promotion",
			"Relay membership and successful MLS join remain insufficient for trust",
		},
	}
	eventPath := filepath.Join(eventRoot, safeBasicLocalTrustPathSegment(normalized.SubjectLabel), eventID+".json")
	if err := writeBasicLocalTrustJSONAtomic(eventPath, event); err != nil {
		return nil, "", err
	}
	return event, eventPath, nil
}

func normalizeBasicLocalTrustInput(input basicLocalTrustInput) basicLocalTrustInput {
	input.StatePath = strings.TrimSpace(input.StatePath)
	input.EventRoot = strings.TrimSpace(input.EventRoot)
	input.SubjectLabel = strings.TrimSpace(input.SubjectLabel)
	input.CypherAccountID = strings.TrimSpace(input.CypherAccountID)
	input.CypherDeviceID = strings.TrimSpace(input.CypherDeviceID)
	input.CommsFingerprint = strings.TrimSpace(input.CommsFingerprint)
	input.OpenMLSDeviceLabel = strings.TrimSpace(input.OpenMLSDeviceLabel)
	input.OpenMLSKeyPackage = strings.TrimSpace(input.OpenMLSKeyPackage)
	input.RelaySpaceID = strings.TrimSpace(input.RelaySpaceID)
	input.Reason = strings.TrimSpace(input.Reason)
	input.SourceReport = strings.TrimSpace(input.SourceReport)
	return input
}

func basicLocalTrustMissingForAcceptance(input basicLocalTrustInput) []string {
	var missing []string
	if input.SubjectLabel == "" {
		missing = append(missing, "subject-label")
	}
	if input.CypherAccountID == "" {
		missing = append(missing, "cypher-account")
	}
	if input.CypherDeviceID == "" {
		missing = append(missing, "cypher-device")
	}
	if input.CommsFingerprint == "" {
		missing = append(missing, "comms-fingerprint")
	}
	return missing
}

func basicLocalTrustStatus(ready bool) string {
	if ready {
		return "manual_local_acceptance_possible_with_explicit_operator_action"
	}
	return "inspect_only_missing_required_local_evidence"
}

func basicLocalTrustNonclaimMap() map[string]bool {
	return map[string]bool{
		"verified_identity":                                 false,
		"trust_promotion":                                   false,
		"secure_enrollment":                                 false,
		"server_hostile_identity_replacement_proof":         false,
		"real_world_person_verification":                    false,
		"cryptographic_binding_across_cypher_comms_openmls": false,
		"automatic_trust_promotion":                         false,
		"relay_membership_trust_authority":                  false,
		"welcome_or_mls_join_trust_authority":               false,
		"production_e2ee":                                   false,
	}
}

func basicLocalTrustNonclaims() []string {
	return []string{
		"not verified identity",
		"not full trust promotion",
		"not secure enrollment",
		"not server-hostile identity replacement proof",
		"not real-world person verification",
		"not cryptographic binding across Cypher, Comms, and OpenMLS identities",
		"not automatic trust promotion",
		"not trust from Relay membership",
		"not trust from successful Welcome or MLS join",
		"not production E2EE",
	}
}

func basicLocalTrustEventID(input basicLocalTrustInput, now time.Time) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		input.SubjectLabel,
		input.CypherAccountID,
		input.CypherDeviceID,
		input.CommsFingerprint,
		input.OpenMLSDeviceLabel,
		input.OpenMLSKeyPackage,
		input.RelaySpaceID,
		input.Reason,
		now.Format(time.RFC3339Nano),
	}, "\n")))
	return now.Format("20060102T150405Z") + "-" + hex.EncodeToString(sum[:])[:16]
}

func safeBasicLocalTrustPathSegment(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	re := basicLocalTrustPostureSlugRE
	value = re.ReplaceAllString(value, "-")
	value = strings.Trim(value, ".-")
	if value == "" {
		return "unknown-subject"
	}
	if len(value) > 80 {
		value = value[:80]
	}
	return value
}

func writeBasicLocalTrustJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func printBasicLocalTrustJSON(value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}
