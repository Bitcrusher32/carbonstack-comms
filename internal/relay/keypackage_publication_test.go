package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
)

func TestKeyPackagePublicationRelayReadsExactArtifact(t *testing.T) {
	artifact := []byte("exact-keypackage-artifact")
	artifactPath := filepath.Join(t.TempDir(), "keypackage.bin")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}

	var request client.PublishRelaySpaceKeyPackageInput
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(
				client.PublishRelaySpaceKeyPackageResponse{
					EnvelopeID:        "envelope-1",
					RelaySpaceID:      "space-1",
					SenderDeviceID:    "sender-1",
					RecipientDeviceID: "recipient-1",
					KeyPackageRef: "sha256:" +
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					PublicationClassification: "created",
					DeliveryState:             "queued",
				},
			)
		},
	))
	defer server.Close()

	response, err := PublishRelaySpaceKeyPackageEnvelope(
		client.New(server.URL),
		"space-1",
		"sender-1",
		"recipient-1",
		"sha256:"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		artifactPath,
		"2026-07-13T05:00:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.EnvelopeID != "envelope-1" {
		t.Fatalf("response = %+v", response)
	}
	decoded, err := base64.StdEncoding.DecodeString(request.CiphertextB64)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(artifact) {
		t.Fatalf("payload = %q", string(decoded))
	}
	if request.KeyPackageRef == "" ||
		request.SenderDeviceID != "sender-1" ||
		request.RecipientDeviceID != "recipient-1" {
		t.Fatalf("request = %+v", request)
	}
}

func TestKeyPackagePublicationRelayRefusesEmptyArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := PublishRelaySpaceKeyPackageEnvelope(
		client.New("http://127.0.0.1:1"),
		"space",
		"sender",
		"recipient",
		"sha256:"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		path,
		"",
	)
	if err == nil {
		t.Fatal("expected empty artifact refusal")
	}
}
