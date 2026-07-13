package relay

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
)

func PublishRelaySpaceKeyPackageEnvelope(
	c client.CypherClient,
	relaySpaceID string,
	senderDeviceID string,
	recipientDeviceID string,
	keyPackageRef string,
	artifactPath string,
	clientCreatedAt string,
) (client.PublishRelaySpaceKeyPackageResponse, error) {
	relaySpaceID = strings.TrimSpace(relaySpaceID)
	senderDeviceID = strings.TrimSpace(senderDeviceID)
	recipientDeviceID = strings.TrimSpace(recipientDeviceID)
	keyPackageRef = strings.TrimSpace(keyPackageRef)
	artifactPath = strings.TrimSpace(artifactPath)

	if relaySpaceID == "" ||
		senderDeviceID == "" ||
		recipientDeviceID == "" ||
		keyPackageRef == "" ||
		artifactPath == "" {
		return client.PublishRelaySpaceKeyPackageResponse{},
			errors.New(
				"relay space, sender, recipient, KeyPackage reference, and artifact path are required",
			)
	}
	payload, err := os.ReadFile(artifactPath)
	if err != nil {
		return client.PublishRelaySpaceKeyPackageResponse{}, err
	}
	if len(payload) == 0 {
		return client.PublishRelaySpaceKeyPackageResponse{},
			errors.New("KeyPackage artifact is empty")
	}
	return c.PublishRelaySpaceKeyPackage(
		relaySpaceID,
		client.PublishRelaySpaceKeyPackageInput{
			SenderDeviceID:    senderDeviceID,
			RecipientDeviceID: recipientDeviceID,
			KeyPackageRef:     keyPackageRef,
			CiphertextB64:     base64.StdEncoding.EncodeToString(payload),
			ClientCreatedAt:   clientCreatedAt,
		},
	)
}
