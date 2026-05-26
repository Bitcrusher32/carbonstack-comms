package protocol

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func assertMessageProtectSuccess(t *testing.T, envelope openMLSSidecarEnvelope, messageLabel string, phase string, groupIDRef string) {
	t.Helper()

	if !envelope.OK {
		t.Fatalf("%s protect ok = false, want true", messageLabel)
	}

	if envelope.Command != "message-protect" {
		t.Fatalf("command = %q, want message-protect", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)

	if envelope.Phase != phase {
		t.Fatalf("%s protect phase = %q, want %q", messageLabel, envelope.Phase, phase)
	}

	if envelope.PrivateMaterialIncluded {
		t.Fatalf("%s protect must not include private material", messageLabel)
	}

	if envelope.Data.MessageLabel != messageLabel {
		t.Fatalf("protect message_label = %q, want %q", envelope.Data.MessageLabel, messageLabel)
	}

	if !envelope.Data.MessageProtected {
		t.Fatalf("%s protect should report message_protected=true", messageLabel)
	}

	if !envelope.Data.ProtectedMessageWritten {
		t.Fatalf("%s protect should report protected_message_written=true", messageLabel)
	}

	if !envelope.Data.ProviderStorageLoaded {
		t.Fatalf("%s protect should report provider_storage_loaded=true", messageLabel)
	}

	if !envelope.Data.ProviderStorageWritten {
		t.Fatalf("%s protect should report provider_storage_written=true", messageLabel)
	}

	if !envelope.Data.GroupReloadable {
		t.Fatalf("%s protect should report group_reloadable=true", messageLabel)
	}

	if envelope.Data.GroupIDRef != groupIDRef {
		t.Fatalf("%s protect group_id_ref = %q, want %q", messageLabel, envelope.Data.GroupIDRef, groupIDRef)
	}

	if envelope.Data.MemberCount != 2 {
		t.Fatalf("%s protect member_count = %d, want 2", messageLabel, envelope.Data.MemberCount)
	}

	if envelope.Data.MessageArtifactPathHint == "" {
		t.Fatalf("%s protect should return message artifact path", messageLabel)
	}

	if envelope.Data.MessageManifestPathHint == "" {
		t.Fatalf("%s protect should return message manifest path", messageLabel)
	}

	if envelope.Data.MessageProtectSummaryPathHint == "" {
		t.Fatalf("%s protect should return message protect summary path", messageLabel)
	}

	if envelope.Data.MessageArtifactSHA256 == "" {
		t.Fatalf("%s protect should return message artifact sha256", messageLabel)
	}

	if envelope.Data.MessageArtifactSizeBytes <= 0 {
		t.Fatalf("%s protect artifact size = %d, want > 0", messageLabel, envelope.Data.MessageArtifactSizeBytes)
	}
}

func assertMessageOpenSuccess(t *testing.T, envelope openMLSSidecarEnvelope, messageLabel string, plaintext string, groupIDRef string) {
	t.Helper()

	if !envelope.OK {
		t.Fatalf("%s open ok = false, want true", messageLabel)
	}

	if envelope.Command != "message-open" {
		t.Fatalf("command = %q, want message-open", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)

	if envelope.Phase != "phase2d-message-open-dev" {
		t.Fatalf("%s open phase = %q, want phase2d-message-open-dev", messageLabel, envelope.Phase)
	}

	if envelope.PrivateMaterialIncluded {
		t.Fatalf("%s open must not include private material", messageLabel)
	}

	if envelope.Data.MessageLabel != messageLabel {
		t.Fatalf("open message_label = %q, want %q", envelope.Data.MessageLabel, messageLabel)
	}

	if !envelope.Data.MessageOpened {
		t.Fatalf("%s open should report message_opened=true", messageLabel)
	}

	if envelope.Data.PlaintextUTF8 != plaintext {
		t.Fatalf("%s open plaintext_utf8 = %q, want %q", messageLabel, envelope.Data.PlaintextUTF8, plaintext)
	}

	if envelope.Data.PlaintextLen != len(plaintext) {
		t.Fatalf("%s open plaintext_len = %d, want %d", messageLabel, envelope.Data.PlaintextLen, len(plaintext))
	}

	if !envelope.Data.ProviderStorageLoaded {
		t.Fatalf("%s open should report provider_storage_loaded=true", messageLabel)
	}

	if !envelope.Data.ProviderStorageWritten {
		t.Fatalf("%s open should report provider_storage_written=true", messageLabel)
	}

	if !envelope.Data.GroupReloadable {
		t.Fatalf("%s open should report group_reloadable=true", messageLabel)
	}

	if envelope.Data.GroupIDRef != groupIDRef {
		t.Fatalf("%s open group_id_ref = %q, want %q", messageLabel, envelope.Data.GroupIDRef, groupIDRef)
	}

	if envelope.Data.MemberCount != 2 {
		t.Fatalf("%s open member_count = %d, want 2", messageLabel, envelope.Data.MemberCount)
	}

	if envelope.Data.MessageOpenSummaryPathHint == "" {
		t.Fatalf("%s open should return message open summary path", messageLabel)
	}
}

func setupOpenMLSTwoMemberConversation(t *testing.T) openMLSSidecarEnvelope {
	t.Helper()

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

	return addMemberEnvelope
}

func protectOpenMLSSidecarMessage(t *testing.T, messageLabel string, plaintext string) openMLSSidecarEnvelope {
	t.Helper()

	protectOutput, protectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", messageLabel,
		"--plaintext", plaintext,
	)
	if protectErr != nil {
		t.Fatalf("%s protect failed: %v\n%s", messageLabel, protectErr, string(protectOutput))
	}

	protectEnvelope := parseSidecarEnvelope(t, protectOutput)
	if !protectEnvelope.OK {
		t.Fatalf("%s protect ok = false, want true", messageLabel)
	}

	assertNoSecretMaterialInStdout(t, protectOutput)

	return protectEnvelope
}

func openOpenMLSSidecarMessage(t *testing.T, messageLabel string, messageArtifactPath string) (openMLSSidecarEnvelope, []byte) {
	t.Helper()

	openOutput, openErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", messageLabel,
		"--message", messageArtifactPath,
	)
	if openErr != nil {
		t.Fatalf("%s open failed: %v\n%s", messageLabel, openErr, string(openOutput))
	}

	openEnvelope := parseSidecarEnvelope(t, openOutput)
	if !openEnvelope.OK {
		t.Fatalf("%s open ok = false, want true", messageLabel)
	}

	return openEnvelope, openOutput
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
