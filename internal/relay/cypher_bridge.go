package relay

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
)

func SubmitOpenMLSArtifactEnvelope(
	c client.CypherClient,
	senderDeviceID string,
	recipientDeviceID string,
	artifactKind string,
	artifactPath string,
	clientCreatedAt string,
) (client.SubmitEnvelopeResponse, error) {
	contentType, err := ContentTypeForArtifactKind(artifactKind)
	if err != nil {
		return client.SubmitEnvelopeResponse{}, err
	}

	payloadB64, err := ReadArtifactPayloadBase64(artifactPath)
	if err != nil {
		return client.SubmitEnvelopeResponse{}, err
	}

	if clientCreatedAt == "" {
		clientCreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	return c.SubmitEnvelope(
		senderDeviceID,
		recipientDeviceID,
		contentType,
		ProtocolVersionOpenMLSSidecar,
		payloadB64,
		clientCreatedAt,
	)
}

func WriteOpenMLSArtifactFromEnvelope(outputPath string, envelope client.EnvelopeRecord) error {
	if !isOpenMLSArtifactContentType(envelope.ContentType) {
		return fmt.Errorf("unsupported OpenMLS artifact content_type: %s", envelope.ContentType)
	}

	if envelope.ProtocolVersion != ProtocolVersionOpenMLSSidecar {
		return fmt.Errorf("unsupported OpenMLS artifact protocol_version: %s", envelope.ProtocolVersion)
	}

	decoded, err := base64.StdEncoding.DecodeString(envelope.CiphertextB64)
	if err != nil {
		return fmt.Errorf("decode envelope ciphertext_b64: %w", err)
	}

	if err := validateEnvelopePayloadMetadata(envelope, decoded); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return fmt.Errorf("create OpenMLS artifact output directory: %w", err)
	}

	return os.WriteFile(outputPath, decoded, 0o600)
}

func SubmitRelaySpaceOpenMLSArtifactEnvelope(
	c client.CypherClient,
	relaySpaceID string,
	senderDeviceID string,
	recipientDeviceID string,
	artifactKind string,
	artifactPath string,
	clientCreatedAt string,
) (client.SubmitRelaySpaceEnvelopeResponse, error) {
	if strings.TrimSpace(relaySpaceID) == "" {
		return client.SubmitRelaySpaceEnvelopeResponse{}, errors.New("relay_space_id is required")
	}

	contentType, err := ContentTypeForArtifactKind(artifactKind)
	if err != nil {
		return client.SubmitRelaySpaceEnvelopeResponse{}, err
	}

	payloadB64, err := ReadArtifactPayloadBase64(artifactPath)
	if err != nil {
		return client.SubmitRelaySpaceEnvelopeResponse{}, err
	}

	if clientCreatedAt == "" {
		clientCreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	return c.SubmitRelaySpaceEnvelope(
		relaySpaceID,
		senderDeviceID,
		recipientDeviceID,
		contentType,
		ProtocolVersionOpenMLSSidecar,
		payloadB64,
		clientCreatedAt,
	)
}

func WriteOpenMLSArtifactFromRelaySpaceEnvelope(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
	if strings.TrimSpace(envelope.RelaySpaceID) == "" {
		return errors.New("relay_space_id is required")
	}

	return WriteOpenMLSArtifactFromEnvelope(outputPath, relaySpaceEnvelopeToEnvelopeRecord(envelope))
}

func relaySpaceEnvelopeToEnvelopeRecord(envelope client.RelaySpaceEnvelopeRecord) client.EnvelopeRecord {
	return client.EnvelopeRecord{
		EnvelopeID:        envelope.EnvelopeID,
		SenderDeviceID:    envelope.SenderDeviceID,
		RecipientDeviceID: envelope.RecipientDeviceID,
		ContentType:       envelope.ContentType,
		ProtocolVersion:   envelope.ProtocolVersion,
		CiphertextB64:     envelope.CiphertextB64,
		PayloadSHA256:     envelope.PayloadSHA256,
		PayloadSizeBytes:  envelope.PayloadSizeBytes,
		ClientCreatedAt:   envelope.ClientCreatedAt,
		ServerReceivedAt:  envelope.ServerReceivedAt,
		DeliveryState:     envelope.DeliveryState,
	}
}

func isOpenMLSArtifactContentType(contentType string) bool {
	switch contentType {
	case ContentTypeOpenMLSKeyPackage,
		ContentTypeOpenMLSWelcome,
		ContentTypeOpenMLSApplicationMessage:
		return true
	default:
		return false
	}
}

func validateEnvelopePayloadMetadata(envelope client.EnvelopeRecord, payload []byte) error {
	if envelope.PayloadSizeBytes != 0 && envelope.PayloadSizeBytes != int64(len(payload)) {
		return fmt.Errorf("payload_size_bytes mismatch: got %d decoded bytes, envelope metadata says %d", len(payload), envelope.PayloadSizeBytes)
	}

	if envelope.PayloadSHA256 != "" {
		hash := sha256.Sum256(payload)
		got := hex.EncodeToString(hash[:])
		if got != envelope.PayloadSHA256 {
			return fmt.Errorf("payload_sha256 mismatch: got %s, envelope metadata says %s", got, envelope.PayloadSHA256)
		}
	}

	return nil
}

func DefaultClientCreatedAt() string {
	return time.Now().UTC().Format(time.RFC3339)
}
