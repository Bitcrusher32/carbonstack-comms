package protocol

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const openMLSSidecarDir = "mls/research/openmls-sidecar"
const openMLSSidecarStateDir = "mls/research/openmls-sidecar/.carbonstack-openmls-sidecar-state"

type openMLSSidecarEnvelope struct {
	OK                      bool                          `json:"ok"`
	Command                 string                        `json:"command"`
	Provider                string                        `json:"provider"`
	Implementation          string                        `json:"implementation"`
	Mode                    string                        `json:"mode"`
	Phase                   string                        `json:"phase"`
	Data                    openMLSSidecarProviderData    `json:"data"`
	Error                   *openMLSSidecarError          `json:"error,omitempty"`
	Events                  []openMLSSidecarProviderEvent `json:"events"`
	Warnings                []string                      `json:"warnings"`
	PrivateMaterialIncluded bool                          `json:"private_material_included"`
}

type openMLSSidecarProviderData struct {
	Capabilities                 []string `json:"capabilities"`
	Unsupported                  []string `json:"unsupported"`
	SecurityLevel                string   `json:"security_level"`
	DeviceLabel                  string   `json:"device_label"`
	IdentityExists               bool     `json:"identity_exists"`
	IdentityLoadable             bool     `json:"identity_loadable"`
	IdentityCreated              bool     `json:"identity_created"`
	StateWritten                 bool     `json:"state_written"`
	StateScope                   string   `json:"state_scope"`
	StatePathHint                string   `json:"state_path_hint"`
	PrepManifestPathHint         string   `json:"prep_manifest_path_hint"`
	IdentitySummaryPathHint      string   `json:"identity_summary_path_hint"`
	IdentityStatePathHint        string   `json:"identity_state_path_hint"`
	SignerPathHint               string   `json:"signer_path_hint"`
	PublicIdentityRef            string   `json:"public_identity_ref"`
	PublicSignatureKeyLen        int      `json:"public_signature_key_len"`
	ManifestPathHint             string   `json:"manifest_path_hint"`
	ProviderStorageWritten       bool     `json:"provider_storage_written"`
	GroupReloadable              bool     `json:"group_reloadable"`
	ConversationLabel            string   `json:"conversation_label"`
	ConversationCreated          bool     `json:"conversation_created"`
	ConversationStatePathHint    string   `json:"conversation_state_path_hint"`
	ConversationSummaryPathHint  string   `json:"conversation_summary_path_hint"`
	Ciphersuite                  string   `json:"ciphersuite"`
	GroupIDRef                   string   `json:"group_id_ref"`
	GroupIDLen                   int      `json:"group_id_len"`
	MemberCount                  int      `json:"member_count"`
	Epoch                        string   `json:"epoch"`
	PublicBundleAvailable        bool     `json:"public_bundle_available"`
	PublicBundleExported         bool     `json:"public_bundle_exported"`
	PublicBundleSummaryPathHint  string   `json:"public_bundle_summary_path_hint"`
	KeyPackageCreated            bool     `json:"key_package_created"`
	KeyPackageArtifactWritten    bool     `json:"key_package_artifact_written"`
	KeyPackageArtifactPathHint   string   `json:"key_package_artifact_path_hint"`
	KeyPackageArtifactSHA256     string   `json:"key_package_artifact_sha256"`
	KeyPackageArtifactSizeBytes  int      `json:"key_package_artifact_size_bytes"`
	PublicBundleManifestWritten  bool     `json:"public_bundle_manifest_written"`
	PublicBundleManifestPathHint string   `json:"public_bundle_manifest_path_hint"`
	KeyPackageRef                string   `json:"key_package_ref"`
	KeyPackageHashLen            int      `json:"key_package_hash_len"`
}

type openMLSSidecarError struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	ProviderEvent string `json:"provider_event"`
	Severity      string `json:"severity"`
	TrustRelevant bool   `json:"trust_relevant"`
}

type openMLSSidecarProviderEvent struct {
	Event         string `json:"event"`
	Severity      string `json:"severity"`
	TrustRelevant bool   `json:"trust_relevant"`
}

func TestOpenMLSSidecarProviderInfoCommand(t *testing.T) {
	output, err := runOpenMLSSidecar("provider-info")
	if err != nil {
		t.Fatalf("run OpenMLS sidecar provider-info: %v", err)
	}

	envelope := parseSidecarEnvelope(t, output)

	if !envelope.OK {
		t.Fatal("provider-info envelope ok = false, want true")
	}

	if envelope.Command != "provider-info" {
		t.Fatalf("command = %q, want provider-info", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)

	if envelope.Phase != "phase2d-provider-info" {
		t.Fatalf("phase = %q, want phase2d-provider-info", envelope.Phase)
	}

	if envelope.PrivateMaterialIncluded {
		t.Fatal("provider-info must not include private material")
	}

	assertStringPresent(t, envelope.Data.Capabilities, "provider-info")
	assertStringPresent(t, envelope.Data.Capabilities, "identity-create")
	assertStringPresent(t, envelope.Data.Capabilities, "identity-status")
	assertStringPresent(t, envelope.Data.Capabilities, "public-bundle-export")
	assertStringPresent(t, envelope.Data.Capabilities, "conversation-create")
	unsupported := []string{
		"conversation-add-member",
		"conversation-join",
		"message-protect",
		"message-open",
		"state-checkpoint",
		"state-load-check",
	}

	for _, command := range unsupported {
		assertStringPresent(t, envelope.Data.Unsupported, command)
	}

	if stringSliceContains(envelope.Data.Unsupported, "identity-create") {
		t.Fatal("identity-create should not be listed as unsupported once command is recognized")
	}

	if envelope.Data.SecurityLevel == "" {
		t.Fatal("expected security level")
	}

	if len(envelope.Warnings) == 0 {
		t.Fatal("expected provider-info warnings")
	}

	if envelope.Error != nil {
		t.Fatalf("provider-info should not include error: %#v", envelope.Error)
	}
}

func TestOpenMLSSidecarUnsupportedCommandEnvelope(t *testing.T) {
	output, err := runOpenMLSSidecar("conversation-add-member")
	assertExitCode(t, err, 2)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("unsupported command envelope ok = true, want false")
	}

	if envelope.Command != "conversation-add-member" {
		t.Fatalf("command = %q, want conversation-add-member", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "unsupported_command", string(ProviderEventCommandUnsupported), "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("unsupported command must not include private material")
	}

	if len(envelope.Events) == 0 {
		t.Fatal("unsupported command should include provider event")
	}
}

func TestOpenMLSSidecarIdentityCreateMissingLabel(t *testing.T) {
	output, err := runOpenMLSSidecar("identity-create")
	assertExitCode(t, err, 2)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("missing-label identity-create envelope ok = true, want false")
	}

	if envelope.Command != "identity-create" {
		t.Fatalf("command = %q, want identity-create", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "missing_required_argument", string(ProviderEventCommandInvalid), "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("missing-label identity-create must not include private material")
	}
}

func TestOpenMLSSidecarIdentityCreateInvalidLabel(t *testing.T) {
	output, err := runOpenMLSSidecar("identity-create", "--device-label", "../bad")
	assertExitCode(t, err, 2)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("invalid-label identity-create envelope ok = true, want false")
	}

	if envelope.Data.DeviceLabel != "../bad" {
		t.Fatalf("device label = %q, want ../bad", envelope.Data.DeviceLabel)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "invalid_device_label", string(ProviderEventCommandInvalid), "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("invalid-label identity-create must not include private material")
	}
}

func TestOpenMLSSidecarIdentityCreateWritesDevIdentityState(t *testing.T) {
	removeOpenMLSSidecarState(t)

	output, err := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if err != nil {
		t.Fatalf("identity-create dev state should exit 0: %v\noutput:\n%s", err, string(output))
	}

	envelope := parseSidecarEnvelope(t, output)

	if !envelope.OK {
		t.Fatal("identity-create dev state envelope ok = false, want true")
	}

	if envelope.Data.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("device label = %q, want carbonstack-alice-device", envelope.Data.DeviceLabel)
	}

	if !envelope.Data.IdentityCreated {
		t.Fatal("identity-create should report identity_created=true")
	}

	if !envelope.Data.StateWritten {
		t.Fatal("identity-create should report state_written=true")
	}

	if envelope.Data.ProviderStorageWritten {
		t.Fatal("identity-create must not claim provider storage was written")
	}

	if envelope.Data.PublicBundleAvailable {
		t.Fatal("identity-create must not claim public bundle is available")
	}

	if envelope.PrivateMaterialIncluded {
		t.Fatal("identity-create must not include private material")
	}

	if envelope.Data.PublicIdentityRef == "" {
		t.Fatal("expected public identity ref")
	}

	if !strings.HasPrefix(envelope.Data.PublicIdentityRef, "sha256:") {
		t.Fatalf("public identity ref = %q, want sha256 prefix", envelope.Data.PublicIdentityRef)
	}

	if envelope.Data.PublicSignatureKeyLen <= 0 {
		t.Fatalf("public signature key length = %d, want positive", envelope.Data.PublicSignatureKeyLen)
	}

	if len(envelope.Events) != 1 {
		t.Fatalf("identity-create event count = %d, want 1", len(envelope.Events))
	}

	if envelope.Events[0].Event != string(ProviderEventIdentityCreated) {
		t.Fatalf("identity-create event = %q, want %q", envelope.Events[0].Event, ProviderEventIdentityCreated)
	}

	if envelope.Events[0].TrustRelevant {
		t.Fatal("identity-created event should not be trust relevant")
	}

	assertNoSecretMaterialInStdout(t, output)

	stateDir := filepath.Join(openMLSSidecarDir, ".carbonstack-openmls-sidecar-state", "dev", "devices", "carbonstack-alice-device")
	prepManifestPath := filepath.Join(stateDir, "identity-prep.json")
	identitySummaryPath := filepath.Join(stateDir, "identity-summary.json")
	identityStatePath := filepath.Join(stateDir, "identity-state.json")
	signerPath := filepath.Join(stateDir, "signer.json")

	assertFileExists(t, prepManifestPath)
	assertFileExists(t, identitySummaryPath)
	assertFileExists(t, identityStatePath)
	assertFileExists(t, signerPath)

	var summary struct {
		SummaryVersion string `json:"summary_version"`
		DeviceLabel    string `json:"device_label"`
		IdentityExists bool   `json:"identity_exists"`

		IdentityLoadable bool `json:"identity_loadable"`

		IdentityCreated             bool   `json:"identity_created"`
		PublicIdentityRef           string `json:"public_identity_ref"`
		PublicSignatureKeyLen       int    `json:"public_signature_key_len"`
		KeyPackageCreated           bool   `json:"key_package_created"`
		PublicBundleAvailable       bool   `json:"public_bundle_available"`
		ProviderStorageWritten      bool   `json:"provider_storage_written"`
		GroupReloadable             bool   `json:"group_reloadable"`
		ConversationLabel           string `json:"conversation_label"`
		ConversationCreated         bool   `json:"conversation_created"`
		ConversationStatePathHint   string `json:"conversation_state_path_hint"`
		ConversationSummaryPathHint string `json:"conversation_summary_path_hint"`
		Ciphersuite                 string `json:"ciphersuite"`
		GroupIDRef                  string `json:"group_id_ref"`
		GroupIDLen                  int    `json:"group_id_len"`
		MemberCount                 int    `json:"member_count"`
		Epoch                       string `json:"epoch"`
		PrivateMaterialIncluded     bool   `json:"private_material_included"`
	}

	readJSONFile(t, identitySummaryPath, &summary)

	if summary.SummaryVersion != "identity-summary/v0" {
		t.Fatalf("summary version = %q, want identity-summary/v0", summary.SummaryVersion)
	}

	if summary.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("summary device label = %q, want carbonstack-alice-device", summary.DeviceLabel)
	}

	if !summary.IdentityCreated {
		t.Fatal("summary should report identity_created=true")
	}

	if summary.PublicIdentityRef == "" || !strings.HasPrefix(summary.PublicIdentityRef, "sha256:") {
		t.Fatalf("summary public identity ref = %q, want sha256 ref", summary.PublicIdentityRef)
	}

	if summary.PublicSignatureKeyLen <= 0 {
		t.Fatalf("summary public signature key length = %d, want positive", summary.PublicSignatureKeyLen)
	}

	if summary.KeyPackageCreated {
		t.Fatal("summary must not claim KeyPackage was created")
	}

	if summary.PublicBundleAvailable {
		t.Fatal("summary must not claim public bundle is available")
	}

	if summary.ProviderStorageWritten {
		t.Fatal("summary must not claim provider storage was written")
	}

	if summary.PrivateMaterialIncluded {
		t.Fatal("summary must not include private material")
	}

	var state struct {
		StateVersion   string `json:"state_version"`
		DeviceLabel    string `json:"device_label"`
		IdentityExists bool   `json:"identity_exists"`

		IdentityLoadable bool `json:"identity_loadable"`

		IdentityCreated             bool   `json:"identity_created"`
		SignerFile                  string `json:"signer_file"`
		ProviderStorageWritten      bool   `json:"provider_storage_written"`
		GroupReloadable             bool   `json:"group_reloadable"`
		ConversationLabel           string `json:"conversation_label"`
		ConversationCreated         bool   `json:"conversation_created"`
		ConversationStatePathHint   string `json:"conversation_state_path_hint"`
		ConversationSummaryPathHint string `json:"conversation_summary_path_hint"`
		Ciphersuite                 string `json:"ciphersuite"`
		GroupIDRef                  string `json:"group_id_ref"`
		GroupIDLen                  int    `json:"group_id_len"`
		MemberCount                 int    `json:"member_count"`
		Epoch                       string `json:"epoch"`
		KeyPackageCreated           bool   `json:"key_package_created"`
		PublicBundleAvailable       bool   `json:"public_bundle_available"`
		PrivateMaterialIncluded     bool   `json:"private_material_included"`
	}

	readJSONFile(t, identityStatePath, &state)

	if state.StateVersion != "identity-state/v0" {
		t.Fatalf("state version = %q, want identity-state/v0", state.StateVersion)
	}

	if state.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("state device label = %q, want carbonstack-alice-device", state.DeviceLabel)
	}

	if !state.IdentityCreated {
		t.Fatal("state should report identity_created=true")
	}

	if state.SignerFile != "signer.json" {
		t.Fatalf("state signer file = %q, want signer.json", state.SignerFile)
	}

	if state.ProviderStorageWritten {
		t.Fatal("state must not claim provider storage was written")
	}

	if state.KeyPackageCreated {
		t.Fatal("state must not claim KeyPackage was created")
	}

	if state.PublicBundleAvailable {
		t.Fatal("state must not claim public bundle is available")
	}

	if state.PrivateMaterialIncluded {
		t.Fatal("state must not include private material")
	}
}

func TestOpenMLSSidecarIdentityCreateRefusesOverwrite(t *testing.T) {
	removeOpenMLSSidecarState(t)

	firstOutput, firstErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if firstErr != nil {
		t.Fatalf("first identity-create should exit 0: %v\noutput:\n%s", firstErr, string(firstOutput))
	}

	secondOutput, secondErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	assertExitCode(t, secondErr, 3)

	envelope := parseSidecarEnvelope(t, secondOutput)

	if envelope.OK {
		t.Fatal("overwrite refusal envelope ok = true, want false")
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "identity_already_exists", string(ProviderEventIdentityExists), "warning", false)

	if envelope.Data.StateWritten {
		t.Fatal("overwrite refusal should not report state_written")
	}

	if envelope.PrivateMaterialIncluded {
		t.Fatal("overwrite refusal must not include private material")
	}

	assertNoSecretMaterialInStdout(t, secondOutput)
}

func TestOpenMLSSidecarIdentityStatusMissing(t *testing.T) {
	removeOpenMLSSidecarState(t)

	output, err := runOpenMLSSidecar("identity-status", "--device-label", "carbonstack-alice-device")
	assertExitCode(t, err, 3)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("missing identity-status envelope ok = true, want false")
	}

	if envelope.Command != "identity-status" {
		t.Fatalf("command = %q, want identity-status", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "identity_missing", string(ProviderEventIdentityMissing), "warning", false)

	if envelope.Data.IdentityExists {
		t.Fatal("missing identity-status should report identity_exists=false")
	}

	if envelope.Data.IdentityLoadable {
		t.Fatal("missing identity-status should report identity_loadable=false")
	}

	if envelope.PrivateMaterialIncluded {
		t.Fatal("missing identity-status must not include private material")
	}

	assertNoSecretMaterialInStdout(t, output)
}

func TestOpenMLSSidecarIdentityStatusLoadsExistingIdentity(t *testing.T) {
	removeOpenMLSSidecarState(t)

	createOutput, createErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if createErr != nil {
		t.Fatalf("identity-create should exit 0 before status: %v\noutput:\n%s", createErr, string(createOutput))
	}

	createEnvelope := parseSidecarEnvelope(t, createOutput)

	statusOutput, statusErr := runOpenMLSSidecar("identity-status", "--device-label", "carbonstack-alice-device")
	if statusErr != nil {
		t.Fatalf("identity-status should exit 0 after create: %v\noutput:\n%s", statusErr, string(statusOutput))
	}

	statusEnvelope := parseSidecarEnvelope(t, statusOutput)

	if !statusEnvelope.OK {
		t.Fatal("identity-status envelope ok = false, want true")
	}

	if statusEnvelope.Command != "identity-status" {
		t.Fatalf("command = %q, want identity-status", statusEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, statusEnvelope)

	if statusEnvelope.Phase != "phase2d-identity-status-dev" {
		t.Fatalf("phase = %q, want phase2d-identity-status-dev", statusEnvelope.Phase)
	}

	if !statusEnvelope.Data.IdentityExists {
		t.Fatal("identity-status should report identity_exists=true")
	}

	if !statusEnvelope.Data.IdentityLoadable {
		t.Fatal("identity-status should report identity_loadable=true")
	}

	if !statusEnvelope.Data.IdentityCreated {
		t.Fatal("identity-status should report identity_created=true")
	}

	if statusEnvelope.Data.ProviderStorageWritten {
		t.Fatal("identity-status must not claim provider storage was written")
	}

	if statusEnvelope.Data.PublicBundleAvailable {
		t.Fatal("identity-status must not claim public bundle is available")
	}

	if statusEnvelope.PrivateMaterialIncluded {
		t.Fatal("identity-status must not include private material")
	}

	if statusEnvelope.Data.PublicIdentityRef == "" {
		t.Fatal("identity-status should return public identity ref")
	}

	if statusEnvelope.Data.PublicIdentityRef != createEnvelope.Data.PublicIdentityRef {
		t.Fatalf("identity-status public identity ref = %q, want create ref %q", statusEnvelope.Data.PublicIdentityRef, createEnvelope.Data.PublicIdentityRef)
	}

	if statusEnvelope.Data.PublicSignatureKeyLen != createEnvelope.Data.PublicSignatureKeyLen {
		t.Fatalf("identity-status public key len = %d, want create len %d", statusEnvelope.Data.PublicSignatureKeyLen, createEnvelope.Data.PublicSignatureKeyLen)
	}

	if len(statusEnvelope.Events) != 1 {
		t.Fatalf("identity-status event count = %d, want 1", len(statusEnvelope.Events))
	}

	if statusEnvelope.Events[0].Event != string(ProviderEventIdentityLoaded) {
		t.Fatalf("identity-status event = %q, want %q", statusEnvelope.Events[0].Event, ProviderEventIdentityLoaded)
	}

	if statusEnvelope.Events[0].TrustRelevant {
		t.Fatal("identity-loaded event should not be trust relevant")
	}

	assertNoSecretMaterialInStdout(t, statusOutput)
}

func TestOpenMLSSidecarPublicBundleExportMissingIdentity(t *testing.T) {
	removeOpenMLSSidecarState(t)

	output, err := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-alice-device")
	assertExitCode(t, err, 3)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("public-bundle-export missing identity envelope ok = true, want false")
	}

	if envelope.Command != "public-bundle-export" {
		t.Fatalf("command = %q, want public-bundle-export", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "identity_missing", string(ProviderEventIdentityMissing), "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("public-bundle-export missing identity must not include private material")
	}

	assertNoSecretMaterialInStdout(t, output)
}

func TestOpenMLSSidecarPublicBundleExportCreatesSummary(t *testing.T) {
	removeOpenMLSSidecarState(t)

	createOutput, createErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if createErr != nil {
		t.Fatalf("identity-create should exit 0 before public-bundle-export: %v\noutput:\n%s", createErr, string(createOutput))
	}

	createEnvelope := parseSidecarEnvelope(t, createOutput)

	exportOutput, exportErr := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-alice-device")
	if exportErr != nil {
		t.Fatalf("public-bundle-export should exit 0 after identity-create: %v\noutput:\n%s", exportErr, string(exportOutput))
	}

	exportEnvelope := parseSidecarEnvelope(t, exportOutput)

	if !exportEnvelope.OK {
		t.Fatal("public-bundle-export envelope ok = false, want true")
	}

	if exportEnvelope.Command != "public-bundle-export" {
		t.Fatalf("command = %q, want public-bundle-export", exportEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, exportEnvelope)

	if exportEnvelope.Phase != "phase2d-public-bundle-export-dev" {
		t.Fatalf("phase = %q, want phase2d-public-bundle-export-dev", exportEnvelope.Phase)
	}

	if !exportEnvelope.Data.IdentityExists {
		t.Fatal("public-bundle-export should report identity_exists=true")
	}

	if !exportEnvelope.Data.IdentityLoadable {
		t.Fatal("public-bundle-export should report identity_loadable=true")
	}

	if !exportEnvelope.Data.PublicBundleExported {
		t.Fatal("public-bundle-export should report public_bundle_exported=true")
	}

	if !exportEnvelope.Data.PublicBundleAvailable {
		t.Fatal("public-bundle-export should report public_bundle_available=true")
	}

	if !exportEnvelope.Data.KeyPackageCreated {
		t.Fatal("public-bundle-export should report key_package_created=true")
	}

	if exportEnvelope.Data.KeyPackageArtifactWritten {
		t.Fatal("public-bundle-export must not claim full KeyPackage artifact was written in this rung")
	}

	if exportEnvelope.Data.ProviderStorageWritten {
		t.Fatal("public-bundle-export must not claim provider storage was written")
	}

	if exportEnvelope.PrivateMaterialIncluded {
		t.Fatal("public-bundle-export must not include private material")
	}

	if exportEnvelope.Data.PublicIdentityRef != createEnvelope.Data.PublicIdentityRef {
		t.Fatalf("public identity ref = %q, want create ref %q", exportEnvelope.Data.PublicIdentityRef, createEnvelope.Data.PublicIdentityRef)
	}

	if exportEnvelope.Data.KeyPackageRef == "" {
		t.Fatal("public-bundle-export should return key package ref")
	}

	if !strings.HasPrefix(exportEnvelope.Data.KeyPackageRef, "sha256:") {
		t.Fatalf("key package ref = %q, want sha256 prefix", exportEnvelope.Data.KeyPackageRef)
	}

	if exportEnvelope.Data.KeyPackageHashLen != 32 {
		t.Fatalf("key package hash len = %d, want 32", exportEnvelope.Data.KeyPackageHashLen)
	}

	if len(exportEnvelope.Events) != 1 {
		t.Fatalf("public-bundle-export event count = %d, want 1", len(exportEnvelope.Events))
	}

	if exportEnvelope.Events[0].Event != string(ProviderEventPublicBundleExported) {
		t.Fatalf("public-bundle-export event = %q, want %q", exportEnvelope.Events[0].Event, ProviderEventPublicBundleExported)
	}

	if exportEnvelope.Events[0].TrustRelevant {
		t.Fatal("public-bundle-export event should not be trust relevant")
	}

	assertNoSecretMaterialInStdout(t, exportOutput)

	stateDir := filepath.Join(openMLSSidecarDir, ".carbonstack-openmls-sidecar-state", "dev", "devices", "carbonstack-alice-device")
	publicBundleSummaryPath := filepath.Join(stateDir, "public-bundle-summary.json")
	signerPath := filepath.Join(stateDir, "signer.json")

	assertFileExists(t, publicBundleSummaryPath)
	assertFileExists(t, signerPath)

	var summary struct {
		SummaryVersion               string `json:"summary_version"`
		DeviceLabel                  string `json:"device_label"`
		PublicIdentityRef            string `json:"public_identity_ref"`
		PublicSignatureKeyLen        int    `json:"public_signature_key_len"`
		KeyPackageCreated            bool   `json:"key_package_created"`
		KeyPackageRef                string `json:"key_package_ref"`
		KeyPackageHashLen            int    `json:"key_package_hash_len"`
		KeyPackageArtifactWritten    bool   `json:"key_package_artifact_written"`
		KeyPackageArtifactPathHint   string `json:"key_package_artifact_path_hint"`
		KeyPackageArtifactSHA256     string `json:"key_package_artifact_sha256"`
		KeyPackageArtifactSizeBytes  int    `json:"key_package_artifact_size_bytes"`
		PublicBundleManifestWritten  bool   `json:"public_bundle_manifest_written"`
		PublicBundleManifestPathHint string `json:"public_bundle_manifest_path_hint"`
		PublicBundleAvailable        bool   `json:"public_bundle_available"`
		ProviderStorageWritten       bool   `json:"provider_storage_written"`
		GroupReloadable              bool   `json:"group_reloadable"`
		ConversationLabel            string `json:"conversation_label"`
		ConversationCreated          bool   `json:"conversation_created"`
		ConversationStatePathHint    string `json:"conversation_state_path_hint"`
		ConversationSummaryPathHint  string `json:"conversation_summary_path_hint"`
		Ciphersuite                  string `json:"ciphersuite"`
		GroupIDRef                   string `json:"group_id_ref"`
		GroupIDLen                   int    `json:"group_id_len"`
		MemberCount                  int    `json:"member_count"`
		Epoch                        string `json:"epoch"`
		PrivateMaterialIncluded      bool   `json:"private_material_included"`
	}

	readJSONFile(t, publicBundleSummaryPath, &summary)

	if summary.SummaryVersion != "public-bundle-summary/v0" {
		t.Fatalf("summary version = %q, want public-bundle-summary/v0", summary.SummaryVersion)
	}

	if summary.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("summary device label = %q, want carbonstack-alice-device", summary.DeviceLabel)
	}

	if summary.PublicIdentityRef != createEnvelope.Data.PublicIdentityRef {
		t.Fatalf("summary public identity ref = %q, want create ref %q", summary.PublicIdentityRef, createEnvelope.Data.PublicIdentityRef)
	}

	if summary.PublicSignatureKeyLen != createEnvelope.Data.PublicSignatureKeyLen {
		t.Fatalf("summary public signature key len = %d, want create len %d", summary.PublicSignatureKeyLen, createEnvelope.Data.PublicSignatureKeyLen)
	}

	if !summary.KeyPackageCreated {
		t.Fatal("summary should report key_package_created=true")
	}

	if summary.KeyPackageRef == "" || !strings.HasPrefix(summary.KeyPackageRef, "sha256:") {
		t.Fatalf("summary key package ref = %q, want sha256 ref", summary.KeyPackageRef)
	}

	if summary.KeyPackageHashLen != 32 {
		t.Fatalf("summary key package hash len = %d, want 32", summary.KeyPackageHashLen)
	}

	if summary.KeyPackageArtifactWritten {
		t.Fatal("summary must not claim full KeyPackage artifact was written")
	}

	if !summary.PublicBundleAvailable {
		t.Fatal("summary should report public_bundle_available=true")
	}

	if summary.ProviderStorageWritten {
		t.Fatal("summary must not claim provider storage was written")
	}

	if summary.PrivateMaterialIncluded {
		t.Fatal("summary must not include private material")
	}
}

func TestOpenMLSSidecarPublicBundleExportWritesArtifact(t *testing.T) {
	removeOpenMLSSidecarState(t)

	createOutput, createErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if createErr != nil {
		t.Fatalf("identity-create should exit 0 before artifact export: %v\noutput:\n%s", createErr, string(createOutput))
	}

	createEnvelope := parseSidecarEnvelope(t, createOutput)

	exportOutput, exportErr := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-alice-device", "--write-artifact")
	if exportErr != nil {
		t.Fatalf("public-bundle-export --write-artifact should exit 0 after identity-create: %v\noutput:\n%s", exportErr, string(exportOutput))
	}

	exportEnvelope := parseSidecarEnvelope(t, exportOutput)

	if !exportEnvelope.OK {
		t.Fatal("artifact public-bundle-export envelope ok = false, want true")
	}

	if exportEnvelope.Command != "public-bundle-export" {
		t.Fatalf("command = %q, want public-bundle-export", exportEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, exportEnvelope)

	if !exportEnvelope.Data.IdentityExists {
		t.Fatal("artifact export should report identity_exists=true")
	}

	if !exportEnvelope.Data.IdentityLoadable {
		t.Fatal("artifact export should report identity_loadable=true")
	}

	if !exportEnvelope.Data.PublicBundleExported {
		t.Fatal("artifact export should report public_bundle_exported=true")
	}

	if !exportEnvelope.Data.PublicBundleAvailable {
		t.Fatal("artifact export should report public_bundle_available=true")
	}

	if !exportEnvelope.Data.KeyPackageCreated {
		t.Fatal("artifact export should report key_package_created=true")
	}

	if !exportEnvelope.Data.KeyPackageArtifactWritten {
		t.Fatal("artifact export should report key_package_artifact_written=true")
	}

	if !exportEnvelope.Data.PublicBundleManifestWritten {
		t.Fatal("artifact export should report public_bundle_manifest_written=true")
	}

	if exportEnvelope.Data.KeyPackageArtifactPathHint == "" {
		t.Fatal("artifact export should return key package artifact path hint")
	}

	if exportEnvelope.Data.PublicBundleManifestPathHint == "" {
		t.Fatal("artifact export should return public bundle manifest path hint")
	}

	if exportEnvelope.Data.KeyPackageArtifactSHA256 == "" || !strings.HasPrefix(exportEnvelope.Data.KeyPackageArtifactSHA256, "sha256:") {
		t.Fatalf("artifact sha256 = %q, want sha256 ref", exportEnvelope.Data.KeyPackageArtifactSHA256)
	}

	if exportEnvelope.Data.KeyPackageArtifactSizeBytes <= 0 {
		t.Fatalf("artifact size = %d, want > 0", exportEnvelope.Data.KeyPackageArtifactSizeBytes)
	}

	if exportEnvelope.Data.ProviderStorageWritten {
		t.Fatal("artifact export must not claim provider storage was written")
	}

	if exportEnvelope.PrivateMaterialIncluded {
		t.Fatal("artifact export must not include private material")
	}

	if exportEnvelope.Data.PublicIdentityRef != createEnvelope.Data.PublicIdentityRef {
		t.Fatalf("artifact export public identity ref = %q, want create ref %q", exportEnvelope.Data.PublicIdentityRef, createEnvelope.Data.PublicIdentityRef)
	}

	if exportEnvelope.Data.KeyPackageRef == "" || !strings.HasPrefix(exportEnvelope.Data.KeyPackageRef, "sha256:") {
		t.Fatalf("artifact export key package ref = %q, want sha256 ref", exportEnvelope.Data.KeyPackageRef)
	}

	if exportEnvelope.Data.KeyPackageHashLen != 32 {
		t.Fatalf("artifact export key package hash len = %d, want 32", exportEnvelope.Data.KeyPackageHashLen)
	}

	if len(exportEnvelope.Events) != 1 {
		t.Fatalf("artifact export event count = %d, want 1", len(exportEnvelope.Events))
	}

	if exportEnvelope.Events[0].Event != string(ProviderEventPublicBundleExported) {
		t.Fatalf("artifact export event = %q, want %q", exportEnvelope.Events[0].Event, ProviderEventPublicBundleExported)
	}

	if exportEnvelope.Events[0].TrustRelevant {
		t.Fatal("artifact export event should not be trust relevant")
	}

	assertNoSecretMaterialInStdout(t, exportOutput)

	stateDir := filepath.Join(openMLSSidecarDir, ".carbonstack-openmls-sidecar-state", "dev", "devices", "carbonstack-alice-device")
	publicBundleSummaryPath := filepath.Join(stateDir, "public-bundle-summary.json")
	publicBundleManifestPath := filepath.Join(stateDir, "public-bundle-manifest.json")
	keyPackageArtifactPath := filepath.Join(stateDir, "public-bundle.keypackage.bin")
	signerPath := filepath.Join(stateDir, "signer.json")

	assertFileExists(t, publicBundleSummaryPath)
	assertFileExists(t, publicBundleManifestPath)
	assertFileExists(t, keyPackageArtifactPath)
	assertFileExists(t, signerPath)

	var summary struct {
		SummaryVersion              string `json:"summary_version"`
		DeviceLabel                 string `json:"device_label"`
		PublicIdentityRef           string `json:"public_identity_ref"`
		PublicSignatureKeyLen       int    `json:"public_signature_key_len"`
		KeyPackageCreated           bool   `json:"key_package_created"`
		KeyPackageRef               string `json:"key_package_ref"`
		KeyPackageHashLen           int    `json:"key_package_hash_len"`
		KeyPackageArtifactWritten   bool   `json:"key_package_artifact_written"`
		KeyPackageArtifactPath      string `json:"key_package_artifact_path"`
		KeyPackageArtifactSHA256    string `json:"key_package_artifact_sha256"`
		KeyPackageArtifactSizeBytes int    `json:"key_package_artifact_size_bytes"`
		PublicBundleManifestWritten bool   `json:"public_bundle_manifest_written"`
		PublicBundleManifestPath    string `json:"public_bundle_manifest_path"`
		PublicBundleAvailable       bool   `json:"public_bundle_available"`
		ProviderStorageWritten      bool   `json:"provider_storage_written"`
		GroupReloadable             bool   `json:"group_reloadable"`
		ConversationLabel           string `json:"conversation_label"`
		ConversationCreated         bool   `json:"conversation_created"`
		ConversationStatePathHint   string `json:"conversation_state_path_hint"`
		ConversationSummaryPathHint string `json:"conversation_summary_path_hint"`
		Ciphersuite                 string `json:"ciphersuite"`
		GroupIDRef                  string `json:"group_id_ref"`
		GroupIDLen                  int    `json:"group_id_len"`
		MemberCount                 int    `json:"member_count"`
		Epoch                       string `json:"epoch"`
		PrivateMaterialIncluded     bool   `json:"private_material_included"`
	}

	readJSONFile(t, publicBundleSummaryPath, &summary)

	if summary.SummaryVersion != "public-bundle-summary/v0" {
		t.Fatalf("summary version = %q, want public-bundle-summary/v0", summary.SummaryVersion)
	}

	if summary.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("summary device label = %q, want carbonstack-alice-device", summary.DeviceLabel)
	}

	if summary.PublicIdentityRef != createEnvelope.Data.PublicIdentityRef {
		t.Fatalf("summary public identity ref = %q, want create ref %q", summary.PublicIdentityRef, createEnvelope.Data.PublicIdentityRef)
	}

	if !summary.KeyPackageCreated {
		t.Fatal("summary should report key_package_created=true")
	}

	if !summary.KeyPackageArtifactWritten {
		t.Fatal("summary should report key_package_artifact_written=true")
	}

	if summary.KeyPackageArtifactPath == "" {
		t.Fatal("summary should include key package artifact path")
	}

	if summary.KeyPackageArtifactSHA256 != exportEnvelope.Data.KeyPackageArtifactSHA256 {
		t.Fatalf("summary artifact sha256 = %q, want envelope sha256 %q", summary.KeyPackageArtifactSHA256, exportEnvelope.Data.KeyPackageArtifactSHA256)
	}

	if summary.KeyPackageArtifactSizeBytes != exportEnvelope.Data.KeyPackageArtifactSizeBytes {
		t.Fatalf("summary artifact size = %d, want envelope size %d", summary.KeyPackageArtifactSizeBytes, exportEnvelope.Data.KeyPackageArtifactSizeBytes)
	}

	if !summary.PublicBundleManifestWritten {
		t.Fatal("summary should report public_bundle_manifest_written=true")
	}

	if summary.PublicBundleManifestPath == "" {
		t.Fatal("summary should include public bundle manifest path")
	}

	if !summary.PublicBundleAvailable {
		t.Fatal("summary should report public_bundle_available=true")
	}

	if summary.ProviderStorageWritten {
		t.Fatal("summary must not claim provider storage was written")
	}

	if summary.PrivateMaterialIncluded {
		t.Fatal("summary must not include private material")
	}

	var manifest struct {
		ManifestVersion             string `json:"manifest_version"`
		DeviceLabel                 string `json:"device_label"`
		StateScope                  string `json:"state_scope"`
		PublicIdentityRef           string `json:"public_identity_ref"`
		PublicSignatureKeyLen       int    `json:"public_signature_key_len"`
		KeyPackageRef               string `json:"key_package_ref"`
		KeyPackageHashLen           int    `json:"key_package_hash_len"`
		KeyPackageArtifact          string `json:"key_package_artifact"`
		KeyPackageArtifactSHA256    string `json:"key_package_artifact_sha256"`
		KeyPackageArtifactSizeBytes int    `json:"key_package_artifact_size_bytes"`
		ProviderStorageWritten      bool   `json:"provider_storage_written"`
		GroupReloadable             bool   `json:"group_reloadable"`
		ConversationLabel           string `json:"conversation_label"`
		ConversationCreated         bool   `json:"conversation_created"`
		ConversationStatePathHint   string `json:"conversation_state_path_hint"`
		ConversationSummaryPathHint string `json:"conversation_summary_path_hint"`
		Ciphersuite                 string `json:"ciphersuite"`
		GroupIDRef                  string `json:"group_id_ref"`
		GroupIDLen                  int    `json:"group_id_len"`
		MemberCount                 int    `json:"member_count"`
		Epoch                       string `json:"epoch"`
		PrivateMaterialIncluded     bool   `json:"private_material_included"`
	}

	readJSONFile(t, publicBundleManifestPath, &manifest)

	if manifest.ManifestVersion != "public-bundle-manifest/v0" {
		t.Fatalf("manifest version = %q, want public-bundle-manifest/v0", manifest.ManifestVersion)
	}

	if manifest.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("manifest device label = %q, want carbonstack-alice-device", manifest.DeviceLabel)
	}

	if manifest.StateScope != "dev-local-sidecar-state" {
		t.Fatalf("manifest state scope = %q, want dev-local-sidecar-state", manifest.StateScope)
	}

	if manifest.PublicIdentityRef != createEnvelope.Data.PublicIdentityRef {
		t.Fatalf("manifest public identity ref = %q, want create ref %q", manifest.PublicIdentityRef, createEnvelope.Data.PublicIdentityRef)
	}

	if manifest.KeyPackageRef != exportEnvelope.Data.KeyPackageRef {
		t.Fatalf("manifest key package ref = %q, want envelope ref %q", manifest.KeyPackageRef, exportEnvelope.Data.KeyPackageRef)
	}

	if manifest.KeyPackageArtifact != "public-bundle.keypackage.bin" {
		t.Fatalf("manifest artifact = %q, want public-bundle.keypackage.bin", manifest.KeyPackageArtifact)
	}

	if manifest.KeyPackageArtifactSHA256 != exportEnvelope.Data.KeyPackageArtifactSHA256 {
		t.Fatalf("manifest artifact sha256 = %q, want envelope sha256 %q", manifest.KeyPackageArtifactSHA256, exportEnvelope.Data.KeyPackageArtifactSHA256)
	}

	if manifest.KeyPackageArtifactSizeBytes != exportEnvelope.Data.KeyPackageArtifactSizeBytes {
		t.Fatalf("manifest artifact size = %d, want envelope size %d", manifest.KeyPackageArtifactSizeBytes, exportEnvelope.Data.KeyPackageArtifactSizeBytes)
	}

	if manifest.ProviderStorageWritten {
		t.Fatal("manifest must not claim provider storage was written")
	}

	if manifest.PrivateMaterialIncluded {
		t.Fatal("manifest must not include private material")
	}

	artifactInfo, err := os.Stat(filepath.Clean(keyPackageArtifactPath))
	if err != nil {
		t.Fatalf("stat artifact: %v", err)
	}

	if int(artifactInfo.Size()) != exportEnvelope.Data.KeyPackageArtifactSizeBytes {
		t.Fatalf("artifact file size = %d, want envelope size %d", artifactInfo.Size(), exportEnvelope.Data.KeyPackageArtifactSizeBytes)
	}

	duplicateOutput, duplicateErr := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-alice-device", "--write-artifact")
	assertExitCode(t, duplicateErr, 4)

	duplicateEnvelope := parseSidecarEnvelope(t, duplicateOutput)

	if duplicateEnvelope.OK {
		t.Fatal("duplicate artifact export envelope ok = true, want false")
	}

	assertSidecarError(t, duplicateEnvelope, "public_bundle_export_failed", "checkpoint.failed", "warning", false)

	assertNoSecretMaterialInStdout(t, duplicateOutput)
}

func TestOpenMLSSidecarConversationCreate(t *testing.T) {
	removeOpenMLSSidecarState(t)

	missingOutput, missingErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	assertExitCode(t, missingErr, 3)

	missingEnvelope := parseSidecarEnvelope(t, missingOutput)

	if missingEnvelope.OK {
		t.Fatal("conversation-create without identity ok = true, want false")
	}

	assertSidecarError(t, missingEnvelope, "identity_missing", string(ProviderEventIdentityMissing), "warning", false)
	assertNoSecretMaterialInStdout(t, missingOutput)

	createOutput, createErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if createErr != nil {
		t.Fatalf("identity-create should exit 0 before conversation-create: %v\noutput:\n%s", createErr, string(createOutput))
	}

	conversationOutput, conversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if conversationErr != nil {
		t.Fatalf("conversation-create should exit 0 after identity-create: %v\noutput:\n%s", conversationErr, string(conversationOutput))
	}

	conversationEnvelope := parseSidecarEnvelope(t, conversationOutput)

	if !conversationEnvelope.OK {
		t.Fatal("conversation-create envelope ok = false, want true")
	}

	if conversationEnvelope.Command != "conversation-create" {
		t.Fatalf("command = %q, want conversation-create", conversationEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, conversationEnvelope)

	if conversationEnvelope.Phase != "phase2d-conversation-create-dev" {
		t.Fatalf("phase = %q, want phase2d-conversation-create-dev", conversationEnvelope.Phase)
	}

	if conversationEnvelope.PrivateMaterialIncluded {
		t.Fatal("conversation-create must not include private material")
	}

	if !conversationEnvelope.Data.IdentityExists {
		t.Fatal("conversation-create should report identity_exists=true")
	}

	if !conversationEnvelope.Data.IdentityLoadable {
		t.Fatal("conversation-create should report identity_loadable=true")
	}

	if !conversationEnvelope.Data.ConversationCreated {
		t.Fatal("conversation-create should report conversation_created=true")
	}

	if conversationEnvelope.Data.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("device label = %q, want carbonstack-alice-device", conversationEnvelope.Data.DeviceLabel)
	}

	if conversationEnvelope.Data.ConversationLabel != "carbonstack-test-conversation" {
		t.Fatalf("conversation label = %q, want carbonstack-test-conversation", conversationEnvelope.Data.ConversationLabel)
	}

	if conversationEnvelope.Data.StateScope != "dev-local-sidecar-state" {
		t.Fatalf("state scope = %q, want dev-local-sidecar-state", conversationEnvelope.Data.StateScope)
	}

	if conversationEnvelope.Data.ConversationStatePathHint == "" {
		t.Fatal("conversation-create should return conversation state path hint")
	}

	if conversationEnvelope.Data.ConversationSummaryPathHint == "" {
		t.Fatal("conversation-create should return conversation summary path hint")
	}

	if conversationEnvelope.Data.Ciphersuite != "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" {
		t.Fatalf("ciphersuite = %q, want current Phase 2D ciphersuite", conversationEnvelope.Data.Ciphersuite)
	}

	if conversationEnvelope.Data.GroupIDRef == "" || !strings.HasPrefix(conversationEnvelope.Data.GroupIDRef, "sha256:") {
		t.Fatalf("group id ref = %q, want sha256 ref", conversationEnvelope.Data.GroupIDRef)
	}

	if conversationEnvelope.Data.GroupIDLen <= 0 {
		t.Fatalf("group id len = %d, want > 0", conversationEnvelope.Data.GroupIDLen)
	}

	if conversationEnvelope.Data.MemberCount != 1 {
		t.Fatalf("member count = %d, want 1", conversationEnvelope.Data.MemberCount)
	}

	if conversationEnvelope.Data.Epoch == "" {
		t.Fatal("conversation-create should return epoch")
	}
	if conversationEnvelope.Data.ProviderStorageWritten {
		t.Fatal("conversation-create must not claim provider_storage_written=true until reloadable provider/group persistence exists")
	}

	if conversationEnvelope.Data.GroupReloadable {
		t.Fatal("conversation-create must not claim group_reloadable=true until MlsGroup::load succeeds across sidecar invocations")
	}

	if len(conversationEnvelope.Events) != 1 {
		t.Fatalf("conversation-create event count = %d, want 1", len(conversationEnvelope.Events))
	}

	if conversationEnvelope.Events[0].Event != string(ProviderEventConversationCreated) {
		t.Fatalf("conversation-create event = %q, want %q", conversationEnvelope.Events[0].Event, ProviderEventConversationCreated)
	}

	if conversationEnvelope.Events[0].TrustRelevant {
		t.Fatal("conversation-create event should not be trust relevant in this dev-sidecar rung")
	}

	assertNoSecretMaterialInStdout(t, conversationOutput)

	stateDir := filepath.Join(openMLSSidecarDir, ".carbonstack-openmls-sidecar-state", "dev", "conversations", "carbonstack-test-conversation")
	conversationSummaryPath := filepath.Join(stateDir, "conversation-summary.json")
	signerPath := filepath.Join(openMLSSidecarDir, ".carbonstack-openmls-sidecar-state", "dev", "devices", "carbonstack-alice-device", "signer.json")

	assertFileExists(t, conversationSummaryPath)
	assertFileExists(t, signerPath)

	var summary struct {
		SummaryVersion          string `json:"summary_version"`
		ConversationLabel       string `json:"conversation_label"`
		CreatorDeviceLabel      string `json:"creator_device_label"`
		StateScope              string `json:"state_scope"`
		Ciphersuite             string `json:"ciphersuite"`
		GroupIDRef              string `json:"group_id_ref"`
		GroupIDLen              int    `json:"group_id_len"`
		MemberCount             int    `json:"member_count"`
		Epoch                   string `json:"epoch"`
		ConversationCreated     bool   `json:"conversation_created"`
		ProviderStorageWritten  bool   `json:"provider_storage_written"`
		GroupReloadable         bool   `json:"group_reloadable"`
		PrivateMaterialIncluded bool   `json:"private_material_included"`
	}

	readJSONFile(t, conversationSummaryPath, &summary)

	if summary.SummaryVersion != "conversation-summary/v0" {
		t.Fatalf("summary version = %q, want conversation-summary/v0", summary.SummaryVersion)
	}

	if summary.ConversationLabel != conversationEnvelope.Data.ConversationLabel {
		t.Fatalf("summary conversation label = %q, want envelope label %q", summary.ConversationLabel, conversationEnvelope.Data.ConversationLabel)
	}

	if summary.CreatorDeviceLabel != conversationEnvelope.Data.DeviceLabel {
		t.Fatalf("summary creator device label = %q, want envelope label %q", summary.CreatorDeviceLabel, conversationEnvelope.Data.DeviceLabel)
	}

	if summary.GroupIDRef != conversationEnvelope.Data.GroupIDRef {
		t.Fatalf("summary group id ref = %q, want envelope ref %q", summary.GroupIDRef, conversationEnvelope.Data.GroupIDRef)
	}

	if summary.GroupIDLen != conversationEnvelope.Data.GroupIDLen {
		t.Fatalf("summary group id len = %d, want envelope len %d", summary.GroupIDLen, conversationEnvelope.Data.GroupIDLen)
	}

	if summary.MemberCount != conversationEnvelope.Data.MemberCount {
		t.Fatalf("summary member count = %d, want envelope count %d", summary.MemberCount, conversationEnvelope.Data.MemberCount)
	}

	if summary.Epoch != conversationEnvelope.Data.Epoch {
		t.Fatalf("summary epoch = %q, want envelope epoch %q", summary.Epoch, conversationEnvelope.Data.Epoch)
	}

	if !summary.ConversationCreated {
		t.Fatal("summary should report conversation_created=true")
	}
	if summary.ProviderStorageWritten {
		t.Fatal("summary must not claim provider_storage_written=true until reloadable provider/group persistence exists")
	}

	if summary.GroupReloadable {
		t.Fatal("summary must not claim group_reloadable=true until MlsGroup::load succeeds across sidecar invocations")
	}

	if summary.PrivateMaterialIncluded {
		t.Fatal("summary must not include private material")
	}

	duplicateOutput, duplicateErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	assertExitCode(t, duplicateErr, 3)

	duplicateEnvelope := parseSidecarEnvelope(t, duplicateOutput)

	if duplicateEnvelope.OK {
		t.Fatal("duplicate conversation-create envelope ok = true, want false")
	}

	assertSidecarError(t, duplicateEnvelope, "conversation_already_exists", string(ProviderEventConversationExists), "warning", false)
	assertNoSecretMaterialInStdout(t, duplicateOutput)

	invalidOutput, invalidErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "../bad")
	assertExitCode(t, invalidErr, 2)

	invalidEnvelope := parseSidecarEnvelope(t, invalidOutput)

	if invalidEnvelope.OK {
		t.Fatal("invalid conversation label envelope ok = true, want false")
	}

	assertSidecarError(t, invalidEnvelope, "invalid_conversation_label", string(ProviderEventCommandInvalid), "warning", false)
	assertNoSecretMaterialInStdout(t, invalidOutput)
}
func runOpenMLSSidecar(args ...string) ([]byte, error) {
	sidecarDir := filepath.Clean(openMLSSidecarDir)

	cmdArgs := append([]string{"run", "--quiet", "--"}, args...)
	cmd := exec.Command("cargo", cmdArgs...)
	cmd.Dir = sidecarDir

	return cmd.Output()
}

func removeOpenMLSSidecarState(t *testing.T) {
	t.Helper()

	if err := os.RemoveAll(filepath.Clean(openMLSSidecarStateDir)); err != nil {
		t.Fatalf("remove sidecar state dir: %v", err)
	}
}

func parseSidecarEnvelope(t *testing.T, output []byte) openMLSSidecarEnvelope {
	t.Helper()

	var envelope openMLSSidecarEnvelope
	if err := json.Unmarshal(output, &envelope); err != nil {
		t.Fatalf("parse sidecar JSON: %v\noutput:\n%s", err, string(output))
	}

	return envelope
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()

	bytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read JSON file %s: %v", path, err)
	}

	if !json.Valid(bytes) {
		t.Fatalf("file is not valid JSON %s:\n%s", path, string(bytes))
	}

	if err := json.Unmarshal(bytes, target); err != nil {
		t.Fatalf("parse JSON file %s: %v", path, err)
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		t.Fatalf("expected file %s: %v", path, err)
	}

	if info.IsDir() {
		t.Fatalf("expected file %s, got directory", path)
	}

	if info.Size() == 0 {
		t.Fatalf("expected file %s to be non-empty", path)
	}
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected exit code %d, got nil error", want)
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("error type = %T, want *exec.ExitError", err)
	}

	if exitErr.ExitCode() != want {
		t.Fatalf("exit code = %d, want %d", exitErr.ExitCode(), want)
	}
}

func assertProviderEnvelopeBase(t *testing.T, envelope openMLSSidecarEnvelope) {
	t.Helper()

	if envelope.Provider != "openmls" {
		t.Fatalf("provider = %q, want openmls", envelope.Provider)
	}

	if envelope.Implementation != "carbonstack-openmls-sidecar" {
		t.Fatalf("implementation = %q, want carbonstack-openmls-sidecar", envelope.Implementation)
	}

	if envelope.Mode != "experimental-sidecar" {
		t.Fatalf("mode = %q, want experimental-sidecar", envelope.Mode)
	}
}

func assertSidecarError(t *testing.T, envelope openMLSSidecarEnvelope, code string, event string, severity string, trustRelevant bool) {
	t.Helper()

	if envelope.Error == nil {
		t.Fatalf("expected sidecar error %q, got nil", code)
	}

	if envelope.Error.Code != code {
		t.Fatalf("error code = %q, want %q", envelope.Error.Code, code)
	}

	if envelope.Error.ProviderEvent != event {
		t.Fatalf("provider event = %q, want %q", envelope.Error.ProviderEvent, event)
	}

	if envelope.Error.Severity != severity {
		t.Fatalf("severity = %q, want %q", envelope.Error.Severity, severity)
	}

	if envelope.Error.TrustRelevant != trustRelevant {
		t.Fatalf("trust relevant = %v, want %v", envelope.Error.TrustRelevant, trustRelevant)
	}
}

func assertNoSecretMaterialInStdout(t *testing.T, output []byte) {
	t.Helper()

	text := strings.ToLower(string(output))

	for _, forbidden := range []string{
		"private_key",
		"privatekey",
		"secret_key",
		"secretkey",
		"signing_key",
		"signingkey",
		"key_store",
		"keystore",
		"memory_storage",
		"memorystorage",
		"recovery",
		"seed",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("stdout appears to contain forbidden secret-related token %q:\n%s", forbidden, string(output))
		}
	}
}

func assertStringPresent(t *testing.T, values []string, want string) {
	t.Helper()

	for _, value := range values {
		if value == want {
			return
		}
	}

	t.Fatalf("expected %q in %#v", want, values)
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}
