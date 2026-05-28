package relay

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	ArtifactKindKeyPackage         = "keypackage"
	ArtifactKindWelcome            = "welcome"
	ArtifactKindApplicationMessage = "application-message"

	ContentTypeOpenMLSKeyPackage         = "carbonstack.mls.keypackage.v0"
	ContentTypeOpenMLSWelcome            = "carbonstack.mls.welcome.v0"
	ContentTypeOpenMLSApplicationMessage = "carbonstack.mls.application-message.v0"

	ProtocolVersionOpenMLSSidecar = "carbonstack-openmls-sidecar-v0"
)

var ErrUnsupportedArtifactKind = errors.New("unsupported OpenMLS artifact kind")

func ContentTypeForArtifactKind(kind string) (string, error) {
	switch kind {
	case ArtifactKindKeyPackage:
		return ContentTypeOpenMLSKeyPackage, nil
	case ArtifactKindWelcome:
		return ContentTypeOpenMLSWelcome, nil
	case ArtifactKindApplicationMessage:
		return ContentTypeOpenMLSApplicationMessage, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedArtifactKind, kind)
	}
}

func ReadArtifactPayload(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("artifact path is required")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, fmt.Errorf("artifact path is a directory: %s", path)
	}

	return os.ReadFile(path)
}

func WriteArtifactPayload(path string, payload []byte) error {
	if path == "" {
		return errors.New("artifact path is required")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	return os.WriteFile(path, payload, 0o600)
}

func EncodePayloadBase64(payload []byte) string {
	return base64.StdEncoding.EncodeToString(payload)
}

func DecodePayloadBase64(payloadB64 string) ([]byte, error) {
	if payloadB64 == "" {
		return nil, errors.New("ciphertext_b64 payload is required")
	}

	return base64.StdEncoding.DecodeString(payloadB64)
}

func ReadArtifactPayloadBase64(path string) (string, error) {
	payload, err := ReadArtifactPayload(path)
	if err != nil {
		return "", err
	}

	return EncodePayloadBase64(payload), nil
}

func WriteArtifactPayloadBase64(path string, payloadB64 string) error {
	payload, err := DecodePayloadBase64(payloadB64)
	if err != nil {
		return err
	}

	return WriteArtifactPayload(path, payload)
}
