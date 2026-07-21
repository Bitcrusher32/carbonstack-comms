package adversarial

import (
	"path/filepath"
	"strings"
)

const GateFCommsNativeProcessProbeSchema = "carbonstack-comms-gate-f-native-process-probe/v0"

type GateFNativeProcessFinding struct {
	CaseID             string `json:"case_id"`
	Status             string `json:"status"`
	Severity           string `json:"severity"`
	FindingDisposition string `json:"finding_disposition"`
	Message            string `json:"message"`
}

func GateFCommsNativeProcessProbeCases() []string {
	return []string{
		"ADV-NATIVE-STATE-ROOT-CONFUSION-001",
		"ADV-NATIVE-PACKAGE-VS-RUNTIME-ROOT-CONFUSION-001",
		"ADV-NATIVE-RESTART-SHUTDOWN-BEHAVIOR-001",
		"ADV-NATIVE-STALE-PROCESS-001",
		"ADV-NATIVE-LOG-LEAKAGE-001",
		"ADV-NATIVE-FILE-PERMISSIONS-001",
		"ADV-NATIVE-GENERATED-ARTIFACTS-001",
		"ADV-NATIVE-LOCAL-CLEANUP-HAZARDS-001",
		"ADV-NATIVE-FOREGROUND-PROCESS-FAILURE-PARTIAL-STATE-001",
		"ADV-NATIVE-CLI-TERMINATING-INSPECTION-001",
	}
}

func GateFPathInsideDisposableRoot(runRoot string, candidate string) bool {
	if strings.TrimSpace(runRoot) == "" || strings.TrimSpace(candidate) == "" {
		return false
	}
	rootAbs, err := filepath.Abs(runRoot)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

func GateFClassifyCommsArtifactPath(runRoot string, candidate string) GateFNativeProcessFinding {
	if !GateFPathInsideDisposableRoot(runRoot, candidate) {
		return GateFNativeProcessFinding{
			CaseID:             "ADV-NATIVE-GENERATED-ARTIFACTS-001",
			Status:             "executed_failed",
			Severity:           "release-blocker",
			FindingDisposition: "failed",
			Message:            "Comms artifact path is outside disposable run root",
		}
	}
	return GateFNativeProcessFinding{
		CaseID:             "ADV-NATIVE-GENERATED-ARTIFACTS-001",
		Status:             "executed_passed",
		Severity:           "informational",
		FindingDisposition: "passed",
		Message:            "Comms artifact path is inside disposable run root",
	}
}

func GateFCommsLogContainsSensitiveMarker(output string) bool {
	lower := strings.ToLower(output)
	for _, marker := range []string{
		"invite token",
		"secret",
		"private key",
		"account_id",
		"device_id",
		"relay_space",
		"keypackage fingerprint",
		"openmls signer",
		"credential fingerprint",
		"state_root",
		"runtime_root",
		"db_path",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func GateFClassifyCommsLogOutput(output string) GateFNativeProcessFinding {
	if GateFCommsLogContainsSensitiveMarker(output) {
		return GateFNativeProcessFinding{
			CaseID:             "ADV-NATIVE-LOG-LEAKAGE-001",
			Status:             "executed_failed",
			Severity:           "release-blocker",
			FindingDisposition: "failed",
			Message:            "Comms output contains sensitive-enough Gate F marker",
		}
	}
	return GateFNativeProcessFinding{
		CaseID:             "ADV-NATIVE-LOG-LEAKAGE-001",
		Status:             "executed_passed",
		Severity:           "informational",
		FindingDisposition: "passed",
		Message:            "Comms output does not contain known Gate F sensitive markers",
	}
}

func GateFClassifyCommsCLIHelp(exitCode int, output string) GateFNativeProcessFinding {
	lower := strings.ToLower(output)
	if exitCode == 0 && (strings.Contains(lower, "usage") || strings.Contains(lower, "help")) {
		return GateFNativeProcessFinding{
			CaseID:             "ADV-NATIVE-CLI-TERMINATING-INSPECTION-001",
			Status:             "executed_passed",
			Severity:           "informational",
			FindingDisposition: "passed",
			Message:            "Comms terminating inspection appears supported",
		}
	}
	return GateFNativeProcessFinding{
		CaseID:             "ADV-NATIVE-CLI-TERMINATING-INSPECTION-001",
		Status:             "executed_failed",
		Severity:           "medium",
		FindingDisposition: "failed",
		Message:            "Comms terminating inspection did not produce a clean help/usage result",
	}
}
