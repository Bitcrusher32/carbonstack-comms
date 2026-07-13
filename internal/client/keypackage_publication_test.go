package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeyPackagePublicationClientRequestAndResponse(t *testing.T) {
	var got PublishRelaySpaceKeyPackageInput
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if r.URL.Path !=
				"/v0/relay-spaces/space-1/keypackage-publications" {
				t.Fatalf("path = %q", r.URL.Path)
			}
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			writeJSON(
				t,
				w,
				http.StatusCreated,
				PublishRelaySpaceKeyPackageResponse{
					EnvelopeID:        "envelope-1",
					RelaySpaceID:      "space-1",
					SenderDeviceID:    "sender-1",
					RecipientDeviceID: "recipient-1",
					KeyPackageRef: "sha256:" +
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					ContentType:      "carbonstack.mls.keypackage.v0",
					ProtocolVersion:  "carbonstack-openmls-sidecar-v0",
					DeliveryState:    "queued",
					ServerReceivedAt: "2026-07-13T05:00:01Z",
					PayloadSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
						"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					PayloadSizeBytes:          10,
					PublicationClassification: "created",
					Idempotent:                false,
				},
			)
		},
	))
	defer server.Close()

	client := New(server.URL + "/")
	input := PublishRelaySpaceKeyPackageInput{
		SenderDeviceID:    "sender-1",
		RecipientDeviceID: "recipient-1",
		KeyPackageRef: "sha256:" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CiphertextB64:   "a2V5cGFja2FnZQ==",
		ClientCreatedAt: "2026-07-13T05:00:00Z",
	}
	response, err := client.PublishRelaySpaceKeyPackage(
		"space-1",
		input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != input {
		t.Fatalf("request = %+v want %+v", got, input)
	}
	if response.EnvelopeID != "envelope-1" ||
		response.PublicationClassification != "created" ||
		response.Idempotent {
		t.Fatalf("response = %+v", response)
	}
}
