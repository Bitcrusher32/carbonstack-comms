package relay

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestContentTypeForArtifactKind(t *testing.T) {
	tests := []struct {
		name        string
		kind        string
		contentType string
	}{
		{
			name:        "keypackage",
			kind:        ArtifactKindKeyPackage,
			contentType: ContentTypeOpenMLSKeyPackage,
		},
		{
			name:        "welcome",
			kind:        ArtifactKindWelcome,
			contentType: ContentTypeOpenMLSWelcome,
		},
		{
			name:        "application message",
			kind:        ArtifactKindApplicationMessage,
			contentType: ContentTypeOpenMLSApplicationMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ContentTypeForArtifactKind(tt.kind)
			if err != nil {
				t.Fatalf("ContentTypeForArtifactKind returned error: %v", err)
			}

			if got != tt.contentType {
				t.Fatalf("content type = %q, want %q", got, tt.contentType)
			}
		})
	}
}

func TestContentTypeForArtifactKindRejectsUnsupportedKind(t *testing.T) {
	_, err := ContentTypeForArtifactKind("signer.json")
	if !errors.Is(err, ErrUnsupportedArtifactKind) {
		t.Fatalf("error = %v, want ErrUnsupportedArtifactKind", err)
	}
}

func TestReadEncodeDecodeWriteArtifactPayload(t *testing.T) {
	dir := t.TempDir()

	sourcePath := filepath.Join(dir, "source", "application-message.bin")
	outputPath := filepath.Join(dir, "output", "application-message.bin")

	want := []byte{0x00, 0x01, 0x02, 0x03, 0xfe, 0xff, 'm', 'l', 's'}

	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}

	if err := os.WriteFile(sourcePath, want, 0o600); err != nil {
		t.Fatalf("write source artifact: %v", err)
	}

	payloadB64, err := ReadArtifactPayloadBase64(sourcePath)
	if err != nil {
		t.Fatalf("ReadArtifactPayloadBase64: %v", err)
	}

	decoded, err := DecodePayloadBase64(payloadB64)
	if err != nil {
		t.Fatalf("DecodePayloadBase64: %v", err)
	}

	if !bytes.Equal(decoded, want) {
		t.Fatalf("decoded payload = %x, want %x", decoded, want)
	}

	if err := WriteArtifactPayloadBase64(outputPath, payloadB64); err != nil {
		t.Fatalf("WriteArtifactPayloadBase64: %v", err)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output artifact: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("output payload = %x, want %x", got, want)
	}
}

func TestDecodePayloadBase64RejectsInvalidPayload(t *testing.T) {
	_, err := DecodePayloadBase64("not valid base64!!!")
	if err == nil {
		t.Fatal("expected invalid base64 error")
	}
}

func TestReadArtifactPayloadRejectsDirectory(t *testing.T) {
	dir := t.TempDir()

	_, err := ReadArtifactPayload(dir)
	if err == nil {
		t.Fatal("expected directory read rejection")
	}
}
