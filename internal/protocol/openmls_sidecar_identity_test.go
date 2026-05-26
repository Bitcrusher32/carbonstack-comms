package protocol

import (
	"os"
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

func TestOpenMLSSidecarMessageProtectOpenOneWay(t *testing.T) {
	removeOpenMLSSidecarState(t)

	aliceIdentityOutput, aliceIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if aliceIdentityErr != nil {
		t.Fatalf("alice identity-create failed: %v\n%s", aliceIdentityErr, string(aliceIdentityOutput))
	}

	bobIdentityOutput, bobIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-bob-device")
	if bobIdentityErr != nil {
		t.Fatalf("bob identity-create failed: %v\n%s", bobIdentityErr, string(bobIdentityOutput))
	}

	bobBundleOutput, bobBundleErr := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-bob-device", "--write-artifact")
	if bobBundleErr != nil {
		t.Fatalf("bob public-bundle-export failed: %v\n%s", bobBundleErr, string(bobBundleOutput))
	}

	bobBundleEnvelope := parseSidecarEnvelope(t, bobBundleOutput)
	if !bobBundleEnvelope.OK {
		t.Fatal("bob public-bundle-export ok = false, want true")
	}

	if !bobBundleEnvelope.Data.ProviderStorageWritten {
		t.Fatal("bob public-bundle-export should persist provider storage for later Welcome consumption")
	}

	if bobBundleEnvelope.Data.KeyPackageArtifactPathHint == "" {
		t.Fatal("bob public-bundle-export should return KeyPackage artifact path")
	}

	aliceConversationOutput, aliceConversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if aliceConversationErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", aliceConversationErr, string(aliceConversationOutput))
	}

	addMemberOutput, addMemberErr := runOpenMLSSidecar(
		"conversation-add-member",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--member-keypackage", bobBundleEnvelope.Data.KeyPackageArtifactPathHint,
	)
	if addMemberErr != nil {
		t.Fatalf("conversation-add-member failed: %v\n%s", addMemberErr, string(addMemberOutput))
	}

	addMemberEnvelope := parseSidecarEnvelope(t, addMemberOutput)
	if !addMemberEnvelope.OK {
		t.Fatal("conversation-add-member ok = false, want true")
	}

	if addMemberEnvelope.Data.WelcomeArtifactPathHint == "" {
		t.Fatal("conversation-add-member should return Welcome artifact path")
	}

	joinOutput, joinErr := runOpenMLSSidecar(
		"conversation-join",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--welcome", addMemberEnvelope.Data.WelcomeArtifactPathHint,
	)
	if joinErr != nil {
		t.Fatalf("conversation-join failed: %v\n%s", joinErr, string(joinOutput))
	}

	joinEnvelope := parseSidecarEnvelope(t, joinOutput)
	if !joinEnvelope.OK {
		t.Fatal("conversation-join ok = false, want true")
	}

	if !joinEnvelope.Data.Joined {
		t.Fatal("conversation-join should report joined=true")
	}

	if joinEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("join group_id_ref = %q, add-member group_id_ref = %q", joinEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	protectOutput, protectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--plaintext", "hello bob",
	)
	if protectErr != nil {
		t.Fatalf("message-protect failed: %v\n%s", protectErr, string(protectOutput))
	}

	protectEnvelope := parseSidecarEnvelope(t, protectOutput)
	if !protectEnvelope.OK {
		t.Fatal("message-protect ok = false, want true")
	}

	if protectEnvelope.Command != "message-protect" {
		t.Fatalf("command = %q, want message-protect", protectEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, protectEnvelope)

	if protectEnvelope.Phase != "phase2d-message-protect-dev" {
		t.Fatalf("phase = %q, want phase2d-message-protect-dev", protectEnvelope.Phase)
	}

	if protectEnvelope.PrivateMaterialIncluded {
		t.Fatal("message-protect must not include private material")
	}

	if !protectEnvelope.Data.MessageProtected {
		t.Fatal("message-protect should report message_protected=true")
	}

	if !protectEnvelope.Data.ProtectedMessageWritten {
		t.Fatal("message-protect should report protected_message_written=true")
	}

	if !protectEnvelope.Data.ProviderStorageLoaded {
		t.Fatal("message-protect should report provider_storage_loaded=true")
	}

	if !protectEnvelope.Data.ProviderStorageWritten {
		t.Fatal("message-protect should report provider_storage_written=true")
	}

	if !protectEnvelope.Data.GroupReloadable {
		t.Fatal("message-protect should report group_reloadable=true")
	}

	if protectEnvelope.Data.MessageArtifactPathHint == "" {
		t.Fatal("message-protect should return message artifact path")
	}

	if protectEnvelope.Data.MessageManifestPathHint == "" {
		t.Fatal("message-protect should return message manifest path")
	}

	if protectEnvelope.Data.MessageProtectSummaryPathHint == "" {
		t.Fatal("message-protect should return message protect summary path")
	}

	if protectEnvelope.Data.MessageArtifactSHA256 == "" {
		t.Fatal("message-protect should return message artifact sha256")
	}

	if protectEnvelope.Data.MessageArtifactSizeBytes <= 0 {
		t.Fatalf("message-protect message artifact size = %d, want > 0", protectEnvelope.Data.MessageArtifactSizeBytes)
	}

	if protectEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("protect group_id_ref = %q, add-member group_id_ref = %q", protectEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	if protectEnvelope.Data.MemberCount != 2 {
		t.Fatalf("message-protect member_count = %d, want 2", protectEnvelope.Data.MemberCount)
	}

	if protectEnvelope.Data.EpochBefore == "" {
		t.Fatal("message-protect should report epoch_before")
	}

	if protectEnvelope.Data.EpochAfter == "" {
		t.Fatal("message-protect should report epoch_after")
	}

	if len(protectEnvelope.Events) != 2 {
		t.Fatalf("message-protect event count = %d, want 2", len(protectEnvelope.Events))
	}

	assertNoSecretMaterialInStdout(t, protectOutput)

	assertFileExists(t, filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageArtifactPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageManifestPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageProtectSummaryPathHint))

	openOutput, openErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message", protectEnvelope.Data.MessageArtifactPathHint,
	)
	if openErr != nil {
		t.Fatalf("message-open failed: %v\n%s", openErr, string(openOutput))
	}

	openEnvelope := parseSidecarEnvelope(t, openOutput)
	if !openEnvelope.OK {
		t.Fatal("message-open ok = false, want true")
	}

	if openEnvelope.Command != "message-open" {
		t.Fatalf("command = %q, want message-open", openEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, openEnvelope)

	if openEnvelope.Phase != "phase2d-message-open-dev" {
		t.Fatalf("phase = %q, want phase2d-message-open-dev", openEnvelope.Phase)
	}

	if openEnvelope.PrivateMaterialIncluded {
		t.Fatal("message-open must not include private material")
	}

	if !openEnvelope.Data.MessageOpened {
		t.Fatal("message-open should report message_opened=true")
	}

	if openEnvelope.Data.PlaintextUTF8 != "hello bob" {
		t.Fatalf("message-open plaintext_utf8 = %q, want hello bob", openEnvelope.Data.PlaintextUTF8)
	}

	if openEnvelope.Data.PlaintextLen != len("hello bob") {
		t.Fatalf("message-open plaintext_len = %d, want %d", openEnvelope.Data.PlaintextLen, len("hello bob"))
	}

	if !openEnvelope.Data.ProviderStorageLoaded {
		t.Fatal("message-open should report provider_storage_loaded=true")
	}

	if !openEnvelope.Data.ProviderStorageWritten {
		t.Fatal("message-open should report provider_storage_written=true")
	}

	if !openEnvelope.Data.GroupReloadable {
		t.Fatal("message-open should report group_reloadable=true")
	}

	if openEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("open group_id_ref = %q, add-member group_id_ref = %q", openEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	if openEnvelope.Data.MemberCount != 2 {
		t.Fatalf("message-open member_count = %d, want 2", openEnvelope.Data.MemberCount)
	}

	if openEnvelope.Data.MessageOpenSummaryPathHint == "" {
		t.Fatal("message-open should return message open summary path")
	}

	if len(openEnvelope.Events) != 2 {
		t.Fatalf("message-open event count = %d, want 2", len(openEnvelope.Events))
	}

	assertNoSecretMaterialInStdout(t, openOutput)

	assertFileExists(t, filepath.Join(openMLSSidecarDir, openEnvelope.Data.MessageOpenSummaryPathHint))

	duplicateProtectOutput, duplicateProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--plaintext", "hello bob again",
	)
	assertExitCode(t, duplicateProtectErr, 3)

	duplicateProtectEnvelope := parseSidecarEnvelope(t, duplicateProtectOutput)
	if duplicateProtectEnvelope.OK {
		t.Fatal("duplicate message-protect envelope ok = true, want false")
	}

	if duplicateProtectEnvelope.Error == nil {
		t.Fatal("duplicate message-protect should include error")
	}

	if duplicateProtectEnvelope.Error.Code != "message_artifact_exists" {
		t.Fatalf("duplicate message-protect error code = %q, want message_artifact_exists", duplicateProtectEnvelope.Error.Code)
	}

	assertNoSecretMaterialInStdout(t, duplicateProtectOutput)
}

func TestOpenMLSSidecarMessageProtectOpenTwoSequentialMessages(t *testing.T) {
	removeOpenMLSSidecarState(t)

	aliceIdentityOutput, aliceIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if aliceIdentityErr != nil {
		t.Fatalf("alice identity-create failed: %v\n%s", aliceIdentityErr, string(aliceIdentityOutput))
	}

	bobIdentityOutput, bobIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-bob-device")
	if bobIdentityErr != nil {
		t.Fatalf("bob identity-create failed: %v\n%s", bobIdentityErr, string(bobIdentityOutput))
	}

	bobBundleOutput, bobBundleErr := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-bob-device", "--write-artifact")
	if bobBundleErr != nil {
		t.Fatalf("bob public-bundle-export failed: %v\n%s", bobBundleErr, string(bobBundleOutput))
	}

	bobBundleEnvelope := parseSidecarEnvelope(t, bobBundleOutput)
	if !bobBundleEnvelope.OK {
		t.Fatal("bob public-bundle-export ok = false, want true")
	}

	if !bobBundleEnvelope.Data.ProviderStorageWritten {
		t.Fatal("bob public-bundle-export should persist provider storage for later Welcome consumption")
	}

	aliceConversationOutput, aliceConversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if aliceConversationErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", aliceConversationErr, string(aliceConversationOutput))
	}

	addMemberOutput, addMemberErr := runOpenMLSSidecar(
		"conversation-add-member",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--member-keypackage", bobBundleEnvelope.Data.KeyPackageArtifactPathHint,
	)
	if addMemberErr != nil {
		t.Fatalf("conversation-add-member failed: %v\n%s", addMemberErr, string(addMemberOutput))
	}

	addMemberEnvelope := parseSidecarEnvelope(t, addMemberOutput)
	if !addMemberEnvelope.OK {
		t.Fatal("conversation-add-member ok = false, want true")
	}

	joinOutput, joinErr := runOpenMLSSidecar(
		"conversation-join",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--welcome", addMemberEnvelope.Data.WelcomeArtifactPathHint,
	)
	if joinErr != nil {
		t.Fatalf("conversation-join failed: %v\n%s", joinErr, string(joinOutput))
	}

	joinEnvelope := parseSidecarEnvelope(t, joinOutput)
	if !joinEnvelope.OK {
		t.Fatal("conversation-join ok = false, want true")
	}

	if joinEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("join group_id_ref = %q, add-member group_id_ref = %q", joinEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	message1ProtectOutput, message1ProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0001",
		"--plaintext", "hello bob 1",
	)
	if message1ProtectErr != nil {
		t.Fatalf("message-0001 protect failed: %v\n%s", message1ProtectErr, string(message1ProtectOutput))
	}

	message1ProtectEnvelope := parseSidecarEnvelope(t, message1ProtectOutput)
	assertMessageProtectSuccess(t, message1ProtectEnvelope, "message-0001", "phase2d-message-protect-dev", addMemberEnvelope.Data.GroupIDRef)

	message1OpenOutput, message1OpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0001",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	if message1OpenErr != nil {
		t.Fatalf("message-0001 open failed: %v\n%s", message1OpenErr, string(message1OpenOutput))
	}

	message1OpenEnvelope := parseSidecarEnvelope(t, message1OpenOutput)
	assertMessageOpenSuccess(t, message1OpenEnvelope, "message-0001", "hello bob 1", addMemberEnvelope.Data.GroupIDRef)

	message2ProtectOutput, message2ProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0002",
		"--plaintext", "hello bob 2",
	)
	if message2ProtectErr != nil {
		t.Fatalf("message-0002 protect failed: %v\n%s", message2ProtectErr, string(message2ProtectOutput))
	}

	message2ProtectEnvelope := parseSidecarEnvelope(t, message2ProtectOutput)
	assertMessageProtectSuccess(t, message2ProtectEnvelope, "message-0002", "phase2d-message-protect-dev", addMemberEnvelope.Data.GroupIDRef)

	if message2ProtectEnvelope.Data.MessageArtifactPathHint == message1ProtectEnvelope.Data.MessageArtifactPathHint {
		t.Fatal("message-0002 artifact path should differ from message-0001 artifact path")
	}

	if message2ProtectEnvelope.Data.MessageArtifactSHA256 == message1ProtectEnvelope.Data.MessageArtifactSHA256 {
		t.Fatal("message-0002 artifact hash should differ from message-0001 artifact hash")
	}

	message2OpenOutput, message2OpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0002",
		"--message", message2ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	if message2OpenErr != nil {
		t.Fatalf("message-0002 open failed: %v\n%s", message2OpenErr, string(message2OpenOutput))
	}

	message2OpenEnvelope := parseSidecarEnvelope(t, message2OpenOutput)
	assertMessageOpenSuccess(t, message2OpenEnvelope, "message-0002", "hello bob 2", addMemberEnvelope.Data.GroupIDRef)

	assertNoSecretMaterialInStdout(t, message1ProtectOutput)
	assertNoSecretMaterialInStdout(t, message1OpenOutput)
	assertNoSecretMaterialInStdout(t, message2ProtectOutput)
	assertNoSecretMaterialInStdout(t, message2OpenOutput)

	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageArtifactPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageManifestPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageProtectSummaryPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1OpenEnvelope.Data.MessageOpenSummaryPathHint))

	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2ProtectEnvelope.Data.MessageArtifactPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2ProtectEnvelope.Data.MessageManifestPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2ProtectEnvelope.Data.MessageProtectSummaryPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2OpenEnvelope.Data.MessageOpenSummaryPathHint))

	duplicateProtectOutput, duplicateProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0002",
		"--plaintext", "hello bob 2 duplicate",
	)
	assertExitCode(t, duplicateProtectErr, 3)

	duplicateProtectEnvelope := parseSidecarEnvelope(t, duplicateProtectOutput)
	if duplicateProtectEnvelope.OK {
		t.Fatal("duplicate message-0002 protect envelope ok = true, want false")
	}

	if duplicateProtectEnvelope.Error == nil {
		t.Fatal("duplicate message-0002 protect should include error")
	}

	if duplicateProtectEnvelope.Error.Code != "message_artifact_exists" {
		t.Fatalf("duplicate message-0002 protect error code = %q, want message_artifact_exists", duplicateProtectEnvelope.Error.Code)
	}

	assertNoSecretMaterialInStdout(t, duplicateProtectOutput)
}

func TestOpenMLSSidecarMessageProtectOpenBidirectional(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	aliceToBobProtectEnvelope := protectOpenMLSSidecarMessage(t, "alice-message-0001", "hello bob from alice")

	aliceToBobOpenEnvelope, aliceToBobOpenOutput := openOpenMLSSidecarMessage(t, "alice-message-0001", aliceToBobProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, aliceToBobOpenEnvelope, "alice-message-0001", "hello bob from alice", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, aliceToBobOpenOutput)

	bobProtectOutput, bobProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "bob-message-0001",
		"--plaintext", "hello alice from bob",
	)
	if bobProtectErr != nil {
		t.Fatalf("bob message-protect failed: %v\n%s", bobProtectErr, string(bobProtectOutput))
	}

	bobProtectEnvelope := parseSidecarEnvelope(t, bobProtectOutput)
	assertMessageProtectSuccess(t, bobProtectEnvelope, "bob-message-0001", "phase2d-message-protect-dev", addMemberEnvelope.Data.GroupIDRef)

	if bobProtectEnvelope.Data.DeviceLabel != "carbonstack-bob-device" {
		t.Fatalf("bob protect device_label = %q, want carbonstack-bob-device", bobProtectEnvelope.Data.DeviceLabel)
	}

	if !strings.Contains(bobProtectEnvelope.Data.MessageArtifactPathHint, "carbonstack-bob-device") {
		t.Fatalf("bob protect artifact path = %q, want Bob device-scoped path", bobProtectEnvelope.Data.MessageArtifactPathHint)
	}

	assertNoSecretMaterialInStdout(t, bobProtectOutput)

	aliceOpenOutput, aliceOpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "bob-message-0001",
		"--message", bobProtectEnvelope.Data.MessageArtifactPathHint,
	)
	if aliceOpenErr != nil {
		t.Fatalf("alice message-open failed: %v\n%s", aliceOpenErr, string(aliceOpenOutput))
	}

	aliceOpenEnvelope := parseSidecarEnvelope(t, aliceOpenOutput)
	assertMessageOpenSuccess(t, aliceOpenEnvelope, "bob-message-0001", "hello alice from bob", addMemberEnvelope.Data.GroupIDRef)

	if aliceOpenEnvelope.Data.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("alice open device_label = %q, want carbonstack-alice-device", aliceOpenEnvelope.Data.DeviceLabel)
	}

	assertNoSecretMaterialInStdout(t, aliceOpenOutput)
}
func TestOpenMLSSidecarMessageOpenWrongDeviceRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	eveIdentityOutput, eveIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-eve-device")
	if eveIdentityErr != nil {
		t.Fatalf("eve identity-create failed: %v\n%s", eveIdentityErr, string(eveIdentityOutput))
	}

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob wrong device probe")

	wrongDeviceOutput, wrongDeviceErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-eve-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "wrong-device-message-0001",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	assertExitCode(t, wrongDeviceErr, 3)

	wrongDeviceEnvelope := parseSidecarEnvelope(t, wrongDeviceOutput)
	if wrongDeviceEnvelope.OK {
		t.Fatal("wrong-device message-open ok = true, want false")
	}

	assertSidecarError(t, wrongDeviceEnvelope, "conversation_or_message_missing", "provider.conversation.missing", "warning", false)

	if wrongDeviceEnvelope.Error == nil {
		t.Fatal("wrong-device message-open should include error")
	}

	if wrongDeviceEnvelope.Error.Message != "device conversation provider storage is missing" {
		t.Fatalf("wrong-device message-open error message = %q, want device conversation provider storage is missing", wrongDeviceEnvelope.Error.Message)
	}

	if wrongDeviceEnvelope.Data.DeviceLabel != "carbonstack-eve-device" {
		t.Fatalf("wrong-device data device_label = %q, want carbonstack-eve-device", wrongDeviceEnvelope.Data.DeviceLabel)
	}

	if wrongDeviceEnvelope.Data.ConversationLabel != addMemberEnvelope.Data.ConversationLabel {
		t.Fatalf("wrong-device data conversation_label = %q, want %q", wrongDeviceEnvelope.Data.ConversationLabel, addMemberEnvelope.Data.ConversationLabel)
	}

	assertNoSecretMaterialInStdout(t, wrongDeviceOutput)
}

func TestOpenMLSSidecarMessageOpenWrongConversationRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob wrong conversation probe")

	wrongConversationOutput, wrongConversationErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-wrong-conversation",
		"--message-label", "wrong-conversation-message-0001",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	assertExitCode(t, wrongConversationErr, 3)

	wrongConversationEnvelope := parseSidecarEnvelope(t, wrongConversationOutput)
	if wrongConversationEnvelope.OK {
		t.Fatal("wrong-conversation message-open ok = true, want false")
	}

	assertSidecarError(t, wrongConversationEnvelope, "conversation_or_message_missing", "provider.conversation.missing", "warning", false)

	if wrongConversationEnvelope.Error == nil {
		t.Fatal("wrong-conversation message-open should include error")
	}

	if wrongConversationEnvelope.Error.Message != "device conversation provider storage is missing" {
		t.Fatalf("wrong-conversation message-open error message = %q, want device conversation provider storage is missing", wrongConversationEnvelope.Error.Message)
	}

	if wrongConversationEnvelope.Data.DeviceLabel != "carbonstack-bob-device" {
		t.Fatalf("wrong-conversation data device_label = %q, want carbonstack-bob-device", wrongConversationEnvelope.Data.DeviceLabel)
	}

	if wrongConversationEnvelope.Data.ConversationLabel != "carbonstack-wrong-conversation" {
		t.Fatalf("wrong-conversation data conversation_label = %q, want carbonstack-wrong-conversation", wrongConversationEnvelope.Data.ConversationLabel)
	}

	assertNoSecretMaterialInStdout(t, wrongConversationOutput)
}
func TestOpenMLSSidecarMessageOpenOutOfOrderTwoMessageDelivery(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob 1")
	message2ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0002", "hello bob 2")

	message2OpenEnvelope, message2OpenOutput := openOpenMLSSidecarMessage(t, "message-0002", message2ProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, message2OpenEnvelope, "message-0002", "hello bob 2", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, message2OpenOutput)

	message1OpenEnvelope, message1OpenOutput := openOpenMLSSidecarMessage(t, "message-0001", message1ProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, message1OpenEnvelope, "message-0001", "hello bob 1", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, message1OpenOutput)
}

func TestOpenMLSSidecarMessageOpenDuplicateRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob 1")

	message1OpenEnvelope, message1OpenOutput := openOpenMLSSidecarMessage(t, "message-0001", message1ProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, message1OpenEnvelope, "message-0001", "hello bob 1", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, message1OpenOutput)

	duplicateOpenOutput, duplicateOpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0001-duplicate",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	assertExitCode(t, duplicateOpenErr, 3)

	duplicateOpenEnvelope := parseSidecarEnvelope(t, duplicateOpenOutput)
	if duplicateOpenEnvelope.OK {
		t.Fatal("duplicate message-open ok = true, want false")
	}

	assertSidecarError(t, duplicateOpenEnvelope, "message_open_failed", "checkpoint.failed", "warning", false)

	if duplicateOpenEnvelope.Error == nil {
		t.Fatal("duplicate message-open should include error")
	}

	if !strings.Contains(duplicateOpenEnvelope.Error.Message, "SecretReuseError") {
		t.Fatalf("duplicate message-open error message = %q, want SecretReuseError", duplicateOpenEnvelope.Error.Message)
	}

	assertNoSecretMaterialInStdout(t, duplicateOpenOutput)
}

func TestOpenMLSSidecarMessageOpenCorruptArtifactRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob 1")

	goodPath := filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageArtifactPathHint)
	badPath := filepath.Join(filepath.Dir(goodPath), "corrupt-application-message.bin")
	badPathHint, relErr := filepath.Rel(openMLSSidecarDir, badPath)
	if relErr != nil {
		t.Fatalf("make corrupt message artifact relative path: %v", relErr)
	}
	badPathHint = "." + string(os.PathSeparator) + badPathHint

	goodBytes, readErr := os.ReadFile(filepath.Clean(goodPath))
	if readErr != nil {
		t.Fatalf("read good message artifact: %v", readErr)
	}

	if len(goodBytes) < 20 {
		t.Fatalf("message artifact too short to truncate safely: len=%d", len(goodBytes))
	}

	truncatedBytes := append([]byte(nil), goodBytes[:len(goodBytes)-10]...)
	if writeErr := os.WriteFile(filepath.Clean(badPath), truncatedBytes, 0o600); writeErr != nil {
		t.Fatalf("write corrupt message artifact: %v", writeErr)
	}

	corruptOpenOutput, corruptOpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "corrupt-message-0001",
		"--message", badPathHint,
	)
	assertExitCode(t, corruptOpenErr, 3)

	corruptOpenEnvelope := parseSidecarEnvelope(t, corruptOpenOutput)
	if corruptOpenEnvelope.OK {
		t.Fatal("corrupt message-open ok = true, want false")
	}

	assertSidecarError(t, corruptOpenEnvelope, "message_artifact_invalid", "provider.message.invalid", "warning", false)

	if corruptOpenEnvelope.Error == nil {
		t.Fatal("corrupt message-open should include error")
	}

	if !strings.Contains(corruptOpenEnvelope.Error.Message, "EndOfStream") {
		t.Fatalf("corrupt message-open error message = %q, want EndOfStream", corruptOpenEnvelope.Error.Message)
	}

	assertNoSecretMaterialInStdout(t, corruptOpenOutput)
}
