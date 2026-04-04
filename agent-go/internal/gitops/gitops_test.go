package gitops

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildCommitReplayBundlePreservesFileModes(t *testing.T) {
	repoDir := t.TempDir()
	runGitCommand(t, repoDir, "init")
	runGitCommand(t, repoDir, "config", "user.email", "test@example.com")
	runGitCommand(t, repoDir, "config", "user.name", "Test User")

	scriptPath := filepath.Join(repoDir, "script.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho hi\n"), 0644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	runGitCommand(t, repoDir, "add", "script.sh")
	runGitCommand(t, repoDir, "commit", "-m", "Add script")
	base := strings.TrimSpace(runGitCommand(t, repoDir, "rev-parse", "HEAD"))

	if err := os.Chmod(scriptPath, 0755); err != nil {
		t.Fatalf("chmod script: %v", err)
	}
	runGitCommand(t, repoDir, "add", "script.sh")
	runGitCommand(t, repoDir, "commit", "-m", "Make script executable")

	bundleJSON, err := buildCommitReplayBundle(repoDir, base)
	if err != nil {
		t.Fatalf("buildCommitReplayBundle: %v", err)
	}

	var bundle commitReplayBundle
	if err := json.Unmarshal([]byte(bundleJSON), &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if len(bundle.Commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(bundle.Commits))
	}
	if len(bundle.Commits[0].Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(bundle.Commits[0].Changes))
	}

	change := bundle.Commits[0].Changes[0]
	if change.Status != "modified" {
		t.Fatalf("expected modified change, got %s", change.Status)
	}
	if change.PreviousMode != "100644" {
		t.Fatalf("expected previous mode 100644, got %q", change.PreviousMode)
	}
	if change.Mode != "100755" {
		t.Fatalf("expected mode 100755, got %q", change.Mode)
	}
	if string(change.PreviousContent) != string(change.Content) {
		t.Fatal("expected chmod-only commit to preserve identical content")
	}
}

func runGitCommand(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\nOutput: %s", args, err, output)
	}
	return string(output)
}
