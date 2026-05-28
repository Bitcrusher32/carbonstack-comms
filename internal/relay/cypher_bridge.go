package relay

import (
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

func WriteOpenMLSArtifactFromEnvelope(path string, envelope client.EnvelopeRecord) error {
	return WriteArtifactPayloadBase64(path, envelope.CiphertextB64)
}
