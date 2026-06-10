package app

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestLegacySendWarnsBeforeRequiredArgFailure(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdSend([]string{})
	})

	if err == nil || !strings.Contains(err.Error(), "--to-device and --message are required") {
		t.Fatalf("expected send required-args error, got %v", err)
	}

	for _, want := range []string{
		"warning: legacy/stub-era send path",
		"warning_replaced_by: openmls-send-dev",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("send output missing %q\n%s", want, output)
		}
	}
}

func TestLegacyInboxWarnsBeforeStateFailure(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdInbox([]string{
			"--state", "testdata/does-not-exist-state.json",
		})
	})

	if err == nil {
		t.Fatal("expected inbox state error")
	}

	for _, want := range []string{
		"warning: legacy/stub-era inbox path",
		"warning_replaced_by: openmls-inbox-dev",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("inbox output missing %q\n%s", want, output)
		}
	}
}

func TestLegacyAckWarnsBeforeRequiredArgFailure(t *testing.T) {
	output, err := captureLegacyWarningOutput(func() error {
		return cmdAck([]string{})
	})

	if err == nil || !strings.Contains(err.Error(), "--envelope is required") {
		t.Fatalf("expected ack required-args error, got %v", err)
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
