package adversarial

import (
	"path/filepath"
	"testing"
)

func TestGateFCommsNativeProcessProbeCases(t *testing.T) {
	if len(GateFCommsNativeProcessProbeCases()) != 10 {
		t.Fatalf("expected 10 Comms Gate F probe cases")
	}
}

func TestGateFCommsArtifactPathMustStayInsideDisposableRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "state", "report.json")
	if got := GateFClassifyCommsArtifactPath(root, inside); got.Status != "executed_passed" {
		t.Fatalf("inside path should pass: %#v", got)
	}
	outside := filepath.Join(filepath.Dir(root), "outside-report.json")
	if got := GateFClassifyCommsArtifactPath(root, outside); got.Status != "executed_failed" || got.Severity != "release-blocker" {
		t.Fatalf("outside path should fail as release-blocker: %#v", got)
	}
}

func TestGateFCommsLogSensitiveMarkers(t *testing.T) {
	if got := GateFClassifyCommsLogOutput("ok: message accepted"); got.Status != "executed_passed" {
		t.Fatalf("safe log should pass: %#v", got)
	}
	if got := GateFClassifyCommsLogOutput("debug account_id=alice device_id=phone"); got.Status != "executed_failed" {
		t.Fatalf("sensitive marker should fail: %#v", got)
	}
}

func TestGateFCommsCLIHelpClassification(t *testing.T) {
	if got := GateFClassifyCommsCLIHelp(0, "Usage: comms [command]"); got.Status != "executed_passed" {
		t.Fatalf("help should pass: %#v", got)
	}
	if got := GateFClassifyCommsCLIHelp(1, "error: unknown command: --help"); got.Status != "executed_failed" || got.Severity != "medium" {
		t.Fatalf("unknown help should be medium finding: %#v", got)
	}
}
