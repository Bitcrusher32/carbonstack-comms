package app

import (
	"bytes"
	"io"
	"os"
)

func captureOutput(fn func()) string {
	oldStdout := os.Stdout
	readPipe, writePipe, _ := os.Pipe()
	os.Stdout = writePipe

	fn()

	_ = writePipe.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, readPipe)
	return buf.String()
}
