package protocol

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type realCypherTestServer struct {
	url     string
	cmd     *exec.Cmd
	logPath string
}

func startRealCypherTestServer(t *testing.T) *realCypherTestServer {
	t.Helper()

	commsRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve comms root: %v", err)
	}

	cypherRoot := resolveTestCypherRoot(t, commsRoot)
	migrationsDir := filepath.Join(cypherRoot, "migrations")

	if _, err := os.Stat(filepath.Join(cypherRoot, "cmd", "cypher", "main.go")); err != nil {
		t.Fatalf("real Cypher repo not found at %s: %v", cypherRoot, err)
	}

	if _, err := os.Stat(migrationsDir); err != nil {
		t.Fatalf("Cypher migrations dir not found at %s: %v", migrationsDir, err)
	}

	tempDir := t.TempDir()
	cypherBinaryPath := filepath.Join(tempDir, "cypher-smoke-test.exe")
	if runtime.GOOS != "windows" {
		cypherBinaryPath = filepath.Join(tempDir, "cypher-smoke-test")
	}

	buildCmd := exec.Command("go", "build", "-o", cypherBinaryPath, "./cmd/cypher")
	buildCmd.Dir = cypherRoot

	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build real Cypher test binary: %v\n%s", err, string(output))
	}

	port := findFreeLocalPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "http://" + addr

	dbPath := filepath.Join(tempDir, "cypher-real-server-smoke.db")
	logPath := filepath.Join(tempDir, "cypher-real-server.log")

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create Cypher log file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, cypherBinaryPath)
	cmd.Dir = cypherRoot
	cmd.Env = append(os.Environ(),
		"CYPHER_ADDR="+addr,
		"CYPHER_DB="+dbPath,
		"CYPHER_MIGRATIONS="+migrationsDir,
		"CYPHER_DEV_INVITE=dev-invite",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		cancel()
		_ = logFile.Close()
		t.Fatalf("start real Cypher server: %v\n%s", err, readFileBestEffort(logPath))
	}

	server := &realCypherTestServer{
		url:     url,
		cmd:     cmd,
		logPath: logPath,
	}

	t.Cleanup(func() {
		cancel()

		if cmd.Process != nil {
			killProcessTreeBestEffort(t, cmd.Process.Pid)
		}

		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Logf("real Cypher process did not exit cleanly after kill")
			}
		}

		_ = logFile.Close()

		if t.Failed() {
			t.Logf("real Cypher server output:\n%s", readFileBestEffort(logPath))
		}
	})

	waitForRealCypherHealth(t, url, logPath)

	return server
}

func (s *realCypherTestServer) URL() string {
	return s.url
}

func findFreeLocalPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free local port: %v", err)
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type: %T", listener.Addr())
	}

	return addr.Port
}

func waitForRealCypherHealth(t *testing.T, serverURL string, logPath string) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	healthURL := serverURL + "/v0/health"

	client := http.Client{
		Timeout: 2 * time.Second,
	}

	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("health returned status %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		time.Sleep(250 * time.Millisecond)
	}

	t.Fatalf("real Cypher server did not become healthy at %s: %v\noutput:\n%s", healthURL, lastErr, readFileBestEffort(logPath))
}

func killProcessTreeBestEffort(t *testing.T, pid int) {
	t.Helper()

	if pid <= 0 {
		return
	}

	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/T", "/F", "/PID", fmt.Sprintf("%d", pid)).Run()
		return
	}

	_ = exec.Command("kill", "-TERM", fmt.Sprintf("%d", pid)).Run()
}

func readFileBestEffort(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(failed to read %s: %v)", path, err)
	}
	return string(body)
}
