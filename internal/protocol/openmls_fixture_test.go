package protocol

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const openMLSFixtureDir = "mls/research/openmls-minimal/fixtures/dev"

type openMLSProviderSummaryFixture struct {
	FixtureVersion string   `json:"fixture_version"`
	ProviderName   string   `json:"provider_name"`
	ProviderMode   string   `json:"provider_mode"`
	Implementation string   `json:"implementation"`
	Ciphersuite    string   `json:"ciphersuite"`
	GroupIDLabel   string   `json:"group_id_label"`
	SecurityLevel  string   `json:"security_level"`
	Warnings       []string `json:"warnings"`
}

type openMLSDeviceSummaryFixture struct {
	DeviceLabel                   string `json:"device_label"`
	Role                          string `json:"role"`
	PublicKeyPackageHashRefLength int    `json:"public_key_package_hash_ref_length"`
	PrivateMaterialIncluded       bool   `json:"private_material_included"`
}

type openMLSInvalidSignatureFixture struct {
	ErrorFixture                string   `json:"error_fixture"`
	SourceObservation           string   `json:"source_observation"`
	OpenMLSError                string   `json:"openmls_error"`
	CarbonStackMappingCandidate string   `json:"carbonstack_mapping_candidate"`
	SuggestedTrustAction        []string `json:"suggested_trust_action"`
	PrivateMaterialIncluded     bool     `json:"private_material_included"`
}

type openMLSProviderEventFixture struct {
	Event string `json:"event"`
}

func TestOpenMLSProviderSummaryFixture(t *testing.T) {
	var summary openMLSProviderSummaryFixture
	readFixtureJSON(t, "provider-summary.json", &summary)

	if summary.FixtureVersion != "provider-fixture-contract/v0" {
		t.Fatalf("unexpected fixture version: %q", summary.FixtureVersion)
	}

	if summary.ProviderName != "openmls" {
		t.Fatalf("unexpected provider name: %q", summary.ProviderName)
	}

	if summary.ProviderMode != "rust-only-scratch" {
		t.Fatalf("unexpected provider mode: %q", summary.ProviderMode)
	}

	if summary.Implementation != "CarbonStackScratchProvider" {
		t.Fatalf("unexpected provider implementation: %q", summary.Implementation)
	}

	if summary.GroupIDLabel == "" {
		t.Fatal("expected group id label")
	}

	if len(summary.Warnings) == 0 {
		t.Fatal("expected fixture warnings")
	}
}

func TestOpenMLSDeviceSummaryFixtures(t *testing.T) {
	var alice openMLSDeviceSummaryFixture
	var bob openMLSDeviceSummaryFixture

	readFixtureJSON(t, "alice-device-summary.json", &alice)
	readFixtureJSON(t, "bob-device-summary.json", &bob)

	assertDeviceFixture(t, alice, "alice")
	assertDeviceFixture(t, bob, "bob")
}

func TestOpenMLSInvalidSignatureFixture(t *testing.T) {
	var fixture openMLSInvalidSignatureFixture
	readFixtureJSON(t, "invalid-signature-error.json", &fixture)

	if fixture.OpenMLSError != "ValidationError(InvalidSignature)" {
		t.Fatalf("unexpected OpenMLS error: %q", fixture.OpenMLSError)
	}

	if fixture.CarbonStackMappingCandidate != "provider.signature.invalid" {
		t.Fatalf("unexpected CarbonStack mapping candidate: %q", fixture.CarbonStackMappingCandidate)
	}

	if fixture.PrivateMaterialIncluded {
		t.Fatal("invalid-signature fixture must not include private material")
	}

	if len(fixture.SuggestedTrustAction) == 0 {
		t.Fatal("expected suggested trust actions")
	}
}

func TestOpenMLSProviderEventFixtureStream(t *testing.T) {
	events := readProviderEvents(t)

	required := []string{
		"provider.fixture.started",
		"provider.public_bundle.created",
		"conversation.created",
		"conversation.welcome.created",
		"conversation.member_added",
		"conversation.welcome.staged",
		"conversation.joined",
		"message.protected",
		"message.opened",
		"conversation.loaded",
		"provider.fixture.completed",
	}

	for _, event := range required {
		if events[event] == 0 {
			t.Fatalf("required event %q not found in provider-events.jsonl", event)
		}
	}

	if events["provider.public_bundle.created"] != 2 {
		t.Fatalf("expected two public bundle events, got %d", events["provider.public_bundle.created"])
	}

	if events["message.protected"] != 2 {
		t.Fatalf("expected two message.protected events, got %d", events["message.protected"])
	}

	if events["message.opened"] != 2 {
		t.Fatalf("expected two message.opened events, got %d", events["message.opened"])
	}
}

func assertDeviceFixture(t *testing.T, fixture openMLSDeviceSummaryFixture, role string) {
	t.Helper()

	if fixture.Role != role {
		t.Fatalf("unexpected role for %s fixture: %q", role, fixture.Role)
	}

	if fixture.DeviceLabel == "" {
		t.Fatalf("expected device label for %s fixture", role)
	}

	if fixture.PublicKeyPackageHashRefLength <= 0 {
		t.Fatalf("expected positive KeyPackage hash ref length for %s fixture", role)
	}

	if fixture.PrivateMaterialIncluded {
		t.Fatalf("%s fixture must not include private material", role)
	}
}

func readFixtureJSON(t *testing.T, name string, target any) {
	t.Helper()

	path := filepath.Join(openMLSFixtureDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
}

func readProviderEvents(t *testing.T) map[string]int {
	t.Helper()

	path := filepath.Join(openMLSFixtureDir, "provider-events.jsonl")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open provider-events.jsonl: %v", err)
	}
	defer file.Close()

	events := map[string]int{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var event openMLSProviderEventFixture
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("parse provider event line: %v", err)
		}

		if event.Event == "" {
			t.Fatal("provider event missing event name")
		}

		events[event.Event]++
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scan provider-events.jsonl: %v", err)
	}

	if len(events) == 0 {
		t.Fatal("expected provider events")
	}

	return events
}
