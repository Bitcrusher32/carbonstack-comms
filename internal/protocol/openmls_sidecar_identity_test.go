package protocol

import (
	"path/filepath"
	"strings"
	"testing"
)

const openMLSSidecarDir = "mls/openmls-sidecar"
const openMLSSidecarStateDir = "mls/openmls-sidecar/.carbonstack-openmls-sidecar-state"

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
	Capabilities                  []string `json:"capabilities"`
	Unsupported                   []string `json:"unsupported"`
	SecurityLevel                 string   `json:"security_level"`
	DeviceLabel                   string   `json:"device_label"`
	IdentityExists                bool     `json:"identity_exists"`
	IdentityLoadable              bool     `json:"identity_loadable"`
	IdentityCreated               bool     `json:"identity_created"`
	StateWritten                  bool     `json:"state_written"`
	StateScope                    string   `json:"state_scope"`
	StatePathHint                 string   `json:"state_path_hint"`
	PrepManifestPathHint          string   `json:"prep_manifest_path_hint"`
	IdentitySummaryPathHint       string   `json:"identity_summary_path_hint"`
	IdentityStatePathHint         string   `json:"identity_state_path_hint"`
	SignerPathHint                string   `json:"signer_path_hint"`
	PublicIdentityRef             string   `json:"public_identity_ref"`
	PublicSignatureKeyLen         int      `json:"public_signature_key_len"`
	ManifestPathHint              string   `json:"manifest_path_hint"`
	ProviderStorageWritten        bool     `json:"provider_storage_written"`
	ProviderStorageLoaded         bool     `json:"provider_storage_loaded"`
	ProviderStoragePathHint       string   `json:"provider_storage_path_hint"`
	GroupReloadable               bool     `json:"group_reloadable"`
	Joined                        bool     `json:"joined"`
	JoinSummaryPathHint           string   `json:"join_summary_path_hint"`
	MessageLabel                  string   `json:"message_label"`
	MessageStatePathHint          string   `json:"message_state_path_hint"`
	MessageArtifactPathHint       string   `json:"message_artifact_path_hint"`
	MessageManifestPathHint       string   `json:"message_manifest_path_hint"`
	MessageProtectSummaryPathHint string   `json:"message_protect_summary_path_hint"`
	MessageOpenSummaryPathHint    string   `json:"message_open_summary_path_hint"`
	MessageArtifactSHA256         string   `json:"message_artifact_sha256"`
	MessageArtifactSizeBytes      int      `json:"message_artifact_size_bytes"`
	MessageProtected              bool     `json:"message_protected"`
	ProtectedMessageWritten       bool     `json:"protected_message_written"`
	MessageOpened                 bool     `json:"message_opened"`
	PlaintextUTF8                 string   `json:"plaintext_utf8"`
	PlaintextLen                  int      `json:"plaintext_len"`
	MemberAdded                   bool     `json:"member_added"`
	WelcomeArtifactWritten        bool     `json:"welcome_artifact_written"`
	PendingCommitMerged           bool     `json:"pending_commit_merged"`
	MemberCountBefore             int      `json:"member_count_before"`
	MemberCountAfter              int      `json:"member_count_after"`
	EpochBefore                   string   `json:"epoch_before"`
	EpochAfter                    string   `json:"epoch_after"`
	MemberKeypackagePathHint      string   `json:"member_keypackage_path_hint"`
	WelcomeArtifactPathHint       string   `json:"welcome_artifact_path_hint"`
	WelcomeManifestPathHint       string   `json:"welcome_manifest_path_hint"`
	AddMemberSummaryPathHint      string   `json:"add_member_summary_path_hint"`
	WelcomeArtifactSHA256         string   `json:"welcome_artifact_sha256"`
	WelcomeArtifactSizeBytes      int      `json:"welcome_artifact_size_bytes"`
	ConversationLabel             string   `json:"conversation_label"`
	ConversationCreated           bool     `json:"conversation_created"`
	ConversationStatePathHint     string   `json:"conversation_state_path_hint"`
	ConversationSummaryPathHint   string   `json:"conversation_summary_path_hint"`
	Ciphersuite                   string   `json:"ciphersuite"`
	GroupIDRef                    string   `json:"group_id_ref"`
	GroupIDLen                    int      `json:"group_id_len"`
	MemberCount                   int      `json:"member_count"`
	Epoch                         string   `json:"epoch"`
	PublicBundleAvailable         bool     `json:"public_bundle_available"`
	PublicBundleExported          bool     `json:"public_bundle_exported"`
	PublicBundleSummaryPathHint   string   `json:"public_bundle_summary_path_hint"`
	KeyPackageCreated             bool     `json:"key_package_created"`
	KeyPackageArtifactWritten     bool     `json:"key_package_artifact_written"`
	KeyPackageArtifactPathHint    string   `json:"key_package_artifact_path_hint"`
	KeyPackageArtifactSHA256      string   `json:"key_package_artifact_sha256"`
	KeyPackageArtifactSizeBytes   int      `json:"key_package_artifact_size_bytes"`
	PublicBundleManifestWritten   bool     `json:"public_bundle_manifest_written"`
	PublicBundleManifestPathHint  string   `json:"public_bundle_manifest_path_hint"`
	KeyPackageRef                 string   `json:"key_package_ref"`
	KeyPackageHashLen             int      `json:"key_package_hash_len"`
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
		ProviderStorageLoaded       bool   `json:"provider_storage_loaded"`
		ProviderStoragePathHint     string `json:"provider_storage_path_hint"`
		GroupReloadable             bool   `json:"group_reloadable"`
		MemberAdded                 bool   `json:"member_added"`
		WelcomeArtifactWritten      bool   `json:"welcome_artifact_written"`
		PendingCommitMerged         bool   `json:"pending_commit_merged"`
		MemberCountBefore           int    `json:"member_count_before"`
		MemberCountAfter            int    `json:"member_count_after"`
		EpochBefore                 string `json:"epoch_before"`
		EpochAfter                  string `json:"epoch_after"`
		MemberKeypackagePathHint    string `json:"member_keypackage_path_hint"`
		WelcomeArtifactPathHint     string `json:"welcome_artifact_path_hint"`
		WelcomeManifestPathHint     string `json:"welcome_manifest_path_hint"`
		AddMemberSummaryPathHint    string `json:"add_member_summary_path_hint"`
		WelcomeArtifactSHA256       string `json:"welcome_artifact_sha256"`
		WelcomeArtifactSizeBytes    int    `json:"welcome_artifact_size_bytes"`
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
		ProviderStorageLoaded       bool   `json:"provider_storage_loaded"`
		ProviderStoragePathHint     string `json:"provider_storage_path_hint"`
		GroupReloadable             bool   `json:"group_reloadable"`
		MemberAdded                 bool   `json:"member_added"`
		WelcomeArtifactWritten      bool   `json:"welcome_artifact_written"`
		PendingCommitMerged         bool   `json:"pending_commit_merged"`
		MemberCountBefore           int    `json:"member_count_before"`
		MemberCountAfter            int    `json:"member_count_after"`
		EpochBefore                 string `json:"epoch_before"`
		EpochAfter                  string `json:"epoch_after"`
		MemberKeypackagePathHint    string `json:"member_keypackage_path_hint"`
		WelcomeArtifactPathHint     string `json:"welcome_artifact_path_hint"`
		WelcomeManifestPathHint     string `json:"welcome_manifest_path_hint"`
		AddMemberSummaryPathHint    string `json:"add_member_summary_path_hint"`
		WelcomeArtifactSHA256       string `json:"welcome_artifact_sha256"`
		WelcomeArtifactSizeBytes    int    `json:"welcome_artifact_size_bytes"`
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
