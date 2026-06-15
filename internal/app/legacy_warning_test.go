package app

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestLegacySendRequiresExplicitOptIn(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdSend([]string{})
	})

	if err == nil || !strings.Contains(err.Error(), "--allow-legacy-stub") {
		t.Fatalf("expected send opt-in error, got %v", err)
	}

	for _, want := range []string{
		"warning: legacy/stub-era send path",
		"warning_replaced_by: message-send-dev",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("send output missing %q\n%s", want, output)
		}
	}
}

func TestLegacySendOptInPreservesRequiredArgFailure(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdSend([]string{"--allow-legacy-stub"})
	})

	if err == nil || !strings.Contains(err.Error(), "--to-device and --message are required") {
		t.Fatalf("expected send required-args error after opt-in, got %v", err)
	}

	if !strings.Contains(output, "warning: legacy/stub-era send path") {
		t.Fatalf("send output missing legacy warning\n%s", output)
	}
}

func TestLegacyInboxRequiresExplicitOptIn(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdInbox([]string{
			"--state", "testdata/does-not-exist-state.json",
		})
	})

	if err == nil || !strings.Contains(err.Error(), "--allow-legacy-stub") {
		t.Fatalf("expected inbox opt-in error, got %v", err)
	}

	for _, want := range []string{
		"warning: legacy/stub-era inbox path",
		"warning_replaced_by: message-inbox-dev",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("inbox output missing %q\n%s", want, output)
		}
	}
}

func TestLegacyInboxOptInPreservesStateFailure(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdInbox([]string{
			"--allow-legacy-stub",
			"--state", "testdata/does-not-exist-state.json",
		})
	})

	if err == nil {
		t.Fatal("expected inbox state error after opt-in")
	}

	if !strings.Contains(output, "warning: legacy/stub-era inbox path") {
		t.Fatalf("inbox output missing legacy warning\n%s", output)
	}
}

func TestLegacyAckRequiresExplicitOptIn(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdAck([]string{})
	})

	if err == nil || !strings.Contains(err.Error(), "--allow-legacy-stub") {
		t.Fatalf("expected ack opt-in error, got %v", err)
	}

	for _, want := range []string{
		"warning: legacy ack helper",
		"warning_scope: delivery/local-processing state only",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("ack output missing %q\n%s", want, output)
		}
	}
}

func TestLegacyAckOptInPreservesRequiredArgFailure(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdAck([]string{"--allow-legacy-stub"})
	})

	if err == nil || !strings.Contains(err.Error(), "--envelope is required") {
		t.Fatalf("expected ack required-args error after opt-in, got %v", err)
	}

	if !strings.Contains(output, "warning: legacy ack helper") {
		t.Fatalf("ack output missing legacy warning\n%s", output)
	}
}

func captureLegacyWarningOutput(fn func() error) (string, error) {
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", err
	}

	os.Stdout = writer
	runErr := fn()

	closeErr := writer.Close()
	os.Stdout = oldStdout
	if closeErr != nil {
		return "", closeErr
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return "", err
	}
	if err := reader.Close(); err != nil {
		return "", err
	}

	return buf.String(), runErr
}
