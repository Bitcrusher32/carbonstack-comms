package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	if !exportEnvelope.Data.ProviderStorageWritten {
		t.Fatal("public-bundle-export should report provider_storage_written=true because KeyPackage private provider state is needed for later Welcome consumption")
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
		ProviderStorageLoaded        bool   `json:"provider_storage_loaded"`
		ProviderStoragePathHint      string `json:"provider_storage_path_hint"`
		GroupReloadable              bool   `json:"group_reloadable"`
		MemberAdded                  bool   `json:"member_added"`
		WelcomeArtifactWritten       bool   `json:"welcome_artifact_written"`
		PendingCommitMerged          bool   `json:"pending_commit_merged"`
		MemberCountBefore            int    `json:"member_count_before"`
		MemberCountAfter             int    `json:"member_count_after"`
		EpochBefore                  string `json:"epoch_before"`
		EpochAfter                   string `json:"epoch_after"`
		MemberKeypackagePathHint     string `json:"member_keypackage_path_hint"`
		WelcomeArtifactPathHint      string `json:"welcome_artifact_path_hint"`
		WelcomeManifestPathHint      string `json:"welcome_manifest_path_hint"`
		AddMemberSummaryPathHint     string `json:"add_member_summary_path_hint"`
		WelcomeArtifactSHA256        string `json:"welcome_artifact_sha256"`
		WelcomeArtifactSizeBytes     int    `json:"welcome_artifact_size_bytes"`
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

	if !summary.ProviderStorageWritten {
		t.Fatal("summary should report provider_storage_written=true after KeyPackage provider storage is saved")
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

	if !exportEnvelope.Data.ProviderStorageWritten {
		t.Fatal("artifact export should report provider_storage_written=true because KeyPackage private provider state is needed for later Welcome consumption")
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

	if !summary.ProviderStorageWritten {
		t.Fatal("summary should report provider_storage_written=true after KeyPackage provider storage is saved")
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

	if !manifest.ProviderStorageWritten {
		t.Fatal("manifest should report provider_storage_written=true after KeyPackage provider storage is saved")
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
