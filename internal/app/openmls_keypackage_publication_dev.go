package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

var runOpenMLSKeyPackagePublicationSidecarForCommand = runOpenMLSBootstrapSidecarForCommand

var publishRelaySpaceKeyPackageForCommand = relay.PublishRelaySpaceKeyPackageEnvelope

type keyPackagePublicationInventory struct {
	DeviceLabel         string                            `json:"device_label"`
	CurrentGenerationID string                            `json:"current_generation_id"`
	Generations         []keyPackagePublicationGeneration `json:"generations"`
}

type keyPackagePublicationGeneration struct {
	GenerationID          string `json:"generation_id"`
	RequestID             string `json:"request_id"`
	KeyPackageRef         string `json:"key_package_ref"`
	ArtifactPath          string `json:"artifact_path"`
	ArtifactSHA256        string `json:"artifact_sha256"`
	ArtifactSizeBytes     int64  `json:"artifact_size_bytes"`
	ManifestPath          string `json:"manifest_path"`
	LifetimeNotBeforeUnix int64  `json:"lifetime_not_before_unix"`
	LifetimeNotAfterUnix  int64  `json:"lifetime_not_after_unix"`
	Status                string `json:"status"`
}

func cmdOpenMLSRelayKeyPackagePublishDev(args []string) error {
	fs := flag.NewFlagSet(
		"openmls-relay-keypackage-publish-dev",
		flag.ContinueOnError,
	)
	statePath := fs.String(
		"state",
		state.DefaultStatePath,
		"local state file path",
	)
	relaySpaceID := fs.String(
		"relay-space",
		"",
		"Relay Space ID",
	)
	toDevice := fs.String(
		"to-device",
		"",
		"recipient Cypher device ID",
	)
	sidecarDir := fs.String(
		"sidecar-dir",
		defaultOpenMLSSidecarDir,
		"OpenMLS sidecar directory",
	)
	sidecarDeviceLabel := fs.String(
		"sidecar-device-label",
		"",
		"OpenMLS sidecar device label",
	)
	generationID := fs.String(
		"generation-id",
		"",
		"existing active KeyPackage generation ID",
	)
	clientCreatedAt := fs.String(
		"client-created-at",
		"",
		"client-created-at override; defaults to current UTC time",
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relaySpaceID) == "" ||
		strings.TrimSpace(*toDevice) == "" ||
		strings.TrimSpace(*sidecarDeviceLabel) == "" ||
		strings.TrimSpace(*generationID) == "" {
		return errors.New(
			"--relay-space, --to-device, --sidecar-device-label, and --generation-id are required",
		)
	}

	localState, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}
	generation, err := inspectKeyPackagePublicationGeneration(
		*sidecarDir,
		*sidecarDeviceLabel,
		*generationID,
	)
	if err != nil {
		return err
	}

	response, err := publishRelaySpaceKeyPackageForCommand(
		client.New(localState.ServerURL),
		*relaySpaceID,
		localState.DeviceID,
		*toDevice,
		generation.KeyPackageRef,
		generation.ArtifactPath,
		*clientCreatedAt,
	)
	if err != nil {
		return err
	}

	fmt.Println("openmls relay KeyPackage publication dev")
	fmt.Println("command: openmls-relay-keypackage-publish-dev")
	fmt.Println("status: published")
	fmt.Printf(
		"publication_classification: %s\n",
		response.PublicationClassification,
	)
	fmt.Printf("idempotent: %t\n", response.Idempotent)
	fmt.Printf("relay_space_id: %s\n", response.RelaySpaceID)
	fmt.Printf("sender_device_id: %s\n", response.SenderDeviceID)
	fmt.Printf("recipient_device_id: %s\n", response.RecipientDeviceID)
	fmt.Printf("sidecar_device_label: %s\n", *sidecarDeviceLabel)
	fmt.Printf("generation_id: %s\n", generation.GenerationID)
	fmt.Printf("generation_request_id: %s\n", generation.RequestID)
	fmt.Printf("key_package_ref: %s\n", generation.KeyPackageRef)
	fmt.Printf("artifact_path: %s\n", generation.ArtifactPath)
	fmt.Printf(
		"generation_manifest_path: %s\n",
		generation.ManifestPath,
	)
	fmt.Printf("artifact_sha256: %s\n", generation.ArtifactSHA256)
	fmt.Printf("payload_sha256: %s\n", response.PayloadSHA256)
	fmt.Printf("payload_size_bytes: %d\n", response.PayloadSizeBytes)
	fmt.Printf("envelope_id: %s\n", response.EnvelopeID)
	fmt.Printf("delivery_state: %s\n", response.DeliveryState)
	fmt.Printf("server_received_at: %s\n", response.ServerReceivedAt)
	fmt.Printf("content_type: %s\n", response.ContentType)
	fmt.Printf("protocol_version: %s\n", response.ProtocolVersion)
	fmt.Println("keypackage_acked: false")
	fmt.Println("welcome_submitted: false")
	fmt.Println("trust_or_candidate_state_mutated: false")
	fmt.Println(
		"warning: dev/pre-alpha publication of one inspected B5b generation; not consumption, Welcome lifecycle, identity verification, trust promotion, or production key distribution",
	)
	return nil
}

func inspectKeyPackagePublicationGeneration(
	sidecarDir string,
	deviceLabel string,
	generationID string,
) (keyPackagePublicationGeneration, error) {
	inventoryEnvelope, err :=
		runOpenMLSKeyPackagePublicationSidecarForCommand(
			sidecarDir,
			"keypackage-inventory",
			"--device-label",
			deviceLabel,
		)
	if err != nil {
		return keyPackagePublicationGeneration{}, err
	}
	var inventory keyPackagePublicationInventory
	rawInventory, err := json.Marshal(inventoryEnvelope.Data)
	if err != nil {
		return keyPackagePublicationGeneration{},
			fmt.Errorf("marshal KeyPackage inventory: %w", err)
	}
	if err := json.Unmarshal(rawInventory, &inventory); err != nil {
		return keyPackagePublicationGeneration{},
			fmt.Errorf("parse KeyPackage inventory: %w", err)
	}
	var selected *keyPackagePublicationGeneration
	for index := range inventory.Generations {
		candidate := &inventory.Generations[index]
		if candidate.GenerationID == generationID {
			selected = candidate
			break
		}
	}
	if selected == nil {
		return keyPackagePublicationGeneration{},
			errors.New("generation_not_found")
	}
	if selected.Status != "active" {
		return keyPackagePublicationGeneration{},
			errors.New("generation_retired")
	}
	if selected.KeyPackageRef == "" ||
		selected.ArtifactPath == "" ||
		selected.ArtifactSHA256 == "" ||
		selected.ArtifactSizeBytes <= 0 ||
		selected.ManifestPath == "" ||
		selected.LifetimeNotBeforeUnix <= 0 ||
		selected.LifetimeNotAfterUnix <=
			selected.LifetimeNotBeforeUnix {
		return keyPackagePublicationGeneration{},
			errors.New("keypackage_inventory_mismatch")
	}

	selected.ArtifactPath = bootstrapPathFromHint(
		sidecarDir,
		selected.ArtifactPath,
	)
	selected.ManifestPath = bootstrapPathFromHint(
		sidecarDir,
		selected.ManifestPath,
	)
	if selected.ArtifactPath == "" || selected.ManifestPath == "" {
		return keyPackagePublicationGeneration{},
			errors.New("keypackage_inventory_mismatch")
	}

	inspection, err :=
		runOpenMLSKeyPackagePublicationSidecarForCommand(
			sidecarDir,
			"keypackage-inspect",
			"--device-label",
			deviceLabel,
			"--keypackage",
			selected.ArtifactPath,
			"--generation-manifest",
			selected.ManifestPath,
		)
	if err != nil {
		return keyPackagePublicationGeneration{}, err
	}
	for field, expected := range map[string]bool{
		"valid_at_inspection_time":  true,
		"openmls_validation_passed": true,
		"owner_match":               true,
		"local_state_mutated":       false,
	} {
		value, ok := inspection.Data[field].(bool)
		if !ok || value != expected {
			return keyPackagePublicationGeneration{},
				errors.New("keypackage_inspection_failed")
		}
	}
	if bootstrapStringField(
		inspection.Data,
		"key_package_ref",
	) != selected.KeyPackageRef ||
		bootstrapStringField(
			inspection.Data,
			"key_package_artifact_sha256",
		) != selected.ArtifactSHA256 ||
		bootstrapIntegerField(
			inspection.Data,
			"key_package_artifact_size_bytes",
		) != selected.ArtifactSizeBytes {
		return keyPackagePublicationGeneration{},
			errors.New("keypackage_inventory_mismatch")
	}
	if bootstrapIntegerField(
		inspection.Data,
		"lifetime_not_before_unix",
	) != selected.LifetimeNotBeforeUnix ||
		bootstrapIntegerField(
			inspection.Data,
			"lifetime_not_after_unix",
		) != selected.LifetimeNotAfterUnix {
		return keyPackagePublicationGeneration{},
			errors.New("keypackage_inventory_mismatch")
	}
	return *selected, nil
}

func bootstrapIntegerField(data map[string]any, key string) int64 {
	value, ok := data[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int:
		return int64(typed)
	case int64:
		return typed
	case json.Number:
		number, _ := typed.Int64()
		return number
	default:
		return 0
	}
}
