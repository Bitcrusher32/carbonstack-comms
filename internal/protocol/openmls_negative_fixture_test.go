package protocol

import "testing"

type openMLSNegativeErrorFixture struct {
	ErrorFixture            string   `json:"error_fixture"`
	ProviderEventCandidate  string   `json:"provider_event_candidate"`
	ProviderClass           string   `json:"provider_class"`
	Severity                string   `json:"severity"`
	TrustRelevant           bool     `json:"trust_relevant"`
	SuggestedAction         []string `json:"suggested_action"`
	PrivateMaterialIncluded bool     `json:"private_material_included"`
}

func TestOpenMLSNegativeErrorFixtures(t *testing.T) {
	cases := []struct {
		file          string
		event         ProviderEventName
		class         ProviderEventClass
		severity      ProviderEventSeverity
		trustRelevant bool
	}{
		{
			file:          "missing-storage-error.json",
			event:         ProviderEventStorageMissing,
			class:         ProviderEventClassStorageCheckpoint,
			severity:      ProviderEventSeverityWarning,
			trustRelevant: false,
		},
		{
			file:          "missing-signer-error.json",
			event:         ProviderEventSecretUnavailable,
			class:         ProviderEventClassTerminalFatal,
			severity:      ProviderEventSeverityFatal,
			trustRelevant: true,
		},
		{
			file:          "wrong-group-error.json",
			event:         ProviderEventGroupUnrecoverable,
			class:         ProviderEventClassTerminalFatal,
			severity:      ProviderEventSeverityFatal,
			trustRelevant: true,
		},
		{
			file:          "malformed-message-error.json",
			event:         ProviderEventTamperDetected,
			class:         ProviderEventClassTrustSecurity,
			severity:      ProviderEventSeveritySecurity,
			trustRelevant: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			var fixture openMLSNegativeErrorFixture
			readFixtureJSON(t, tc.file, &fixture)

			if fixture.PrivateMaterialIncluded {
				t.Fatal("negative fixture must not include private material")
			}

			if fixture.ProviderEventCandidate != string(tc.event) {
				t.Fatalf("event candidate = %q, want %q", fixture.ProviderEventCandidate, tc.event)
			}

			if fixture.ProviderClass != string(tc.class) {
				t.Fatalf("provider class = %q, want %q", fixture.ProviderClass, tc.class)
			}

			if fixture.Severity != string(tc.severity) {
				t.Fatalf("severity = %q, want %q", fixture.Severity, tc.severity)
			}

			if fixture.TrustRelevant != tc.trustRelevant {
				t.Fatalf("trust relevant = %v, want %v", fixture.TrustRelevant, tc.trustRelevant)
			}

			if len(fixture.SuggestedAction) == 0 {
				t.Fatal("expected suggested actions")
			}

			descriptor := DescribeProviderEvent(tc.event)
			if descriptor.Class != tc.class {
				t.Fatalf("descriptor class = %q, want %q", descriptor.Class, tc.class)
			}

			if descriptor.Severity != tc.severity {
				t.Fatalf("descriptor severity = %q, want %q", descriptor.Severity, tc.severity)
			}

			if descriptor.TrustRelevant != tc.trustRelevant {
				t.Fatalf("descriptor trust relevant = %v, want %v", descriptor.TrustRelevant, tc.trustRelevant)
			}
		})
	}
}
