package trust

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerprintIsStableAndFormatted(t *testing.T) {
	first := Fingerprint("stub-public-key")
	second := Fingerprint("stub-public-key")

	if first != second {
		t.Fatalf("expected stable fingerprint")
	}

	if !strings.HasPrefix(first, "CSFP-") {
		t.Fatalf("expected CSFP prefix, got %s", first)
	}
}

func TestVerifyDeviceStoresTrustAndEvent(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	record, err := VerifyDevice(paths, "account-1", "device-1", "alice-device", "stub-public-key", "test")
	if err != nil {
		t.Fatalf("verify device: %v", err)
	}

	if record.TrustState != StateVerified {
		t.Fatalf("expected verified, got %s", record.TrustState)
	}

	found, ok, err := LookupDevice(paths, "device-1")
	if err != nil {
		t.Fatalf("lookup device: %v", err)
	}
	if !ok {
		t.Fatalf("expected device in trust store")
	}
	if found.Fingerprint != Fingerprint("stub-public-key") {
		t.Fatalf("fingerprint mismatch")
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 trust event, got %d", len(events))
	}
	if events[0].EventType != "device_verified" {
		t.Fatalf("expected device_verified event, got %s", events[0].EventType)
	}
}

func TestEvaluateSendUnknownDeviceDevAndStrict(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	devDecision, err := EvaluateSend(paths, "missing-device", false)
	if err != nil {
		t.Fatalf("evaluate dev send: %v", err)
	}
	if !devDecision.Allowed {
		t.Fatalf("expected dev mode to allow unknown device")
	}

	strictDecision, err := EvaluateSend(paths, "missing-device", true)
	if err != nil {
		t.Fatalf("evaluate strict send: %v", err)
	}
	if strictDecision.Allowed {
		t.Fatalf("expected strict mode to block unknown device")
	}
}

func TestEvaluateSendVerifiedDevice(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	_, err := VerifyDevice(paths, "account-1", "device-1", "alice-device", "stub-public-key", "test")
	if err != nil {
		t.Fatalf("verify device: %v", err)
	}

	decision, err := EvaluateSend(paths, "device-1", true)
	if err != nil {
		t.Fatalf("evaluate send: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected verified device to be allowed")
	}
}

func TestChangedDeviceBlocksInStrictMode(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	_, err := VerifyDevice(paths, "account-1", "device-1", "alice-device", "old-key", "test")
	if err != nil {
		t.Fatalf("verify device: %v", err)
	}

	_, err = MarkDeviceChanged(paths, "device-1", "new-key", "test")
	if err != nil {
		t.Fatalf("mark changed: %v", err)
	}

	decision, err := EvaluateSend(paths, "device-1", true)
	if err != nil {
		t.Fatalf("evaluate send: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected changed device to block in strict mode")
	}
}

func TestRevokedDeviceAlwaysBlocks(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	_, err := VerifyDevice(paths, "account-1", "device-1", "alice-device", "stub-public-key", "test")
	if err != nil {
		t.Fatalf("verify device: %v", err)
	}

	_, err = RevokeDevice(paths, "device-1", "test")
	if err != nil {
		t.Fatalf("revoke device: %v", err)
	}

	decision, err := EvaluateSend(paths, "device-1", false)
	if err != nil {
		t.Fatalf("evaluate send: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected revoked device to block")
	}
}
