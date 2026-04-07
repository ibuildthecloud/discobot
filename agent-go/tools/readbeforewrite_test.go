package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Write guard tests ---

func TestReadBeforeWrite_NewFileNoReadRequired(t *testing.T) {
	e := New(t.TempDir(), t.TempDir(), t.Name())
	// File does not exist yet — Write should succeed without a prior Read.
	out, ok := runTool(t, e, "Write", map[string]any{
		"file_path": "new.txt",
		"content":   "hello\n",
	})
	if !ok {
		t.Fatalf("expected success writing new file, got: %s", out)
	}
}

func TestReadBeforeWrite_ExistingFileWithoutRead_Write(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "file.txt"), []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	out, ok := runTool(t, e, "Write", map[string]any{
		"file_path": "file.txt",
		"content":   "overwrite\n",
	})
	if ok {
		t.Error("expected error when writing existing file without prior read, got success")
	}
	if !strings.Contains(out, "read") {
		t.Errorf("expected 'read' hint in error message, got: %q", out)
	}
	// File must be unchanged.
	data, _ := os.ReadFile(filepath.Join(cwd, "file.txt"))
	if string(data) != "original\n" {
		t.Errorf("file was modified despite no prior read: %q", string(data))
	}
}

func TestReadBeforeWrite_ExistingFileAfterRead_Write(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "file.txt"), []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.txt")
	out, ok := runTool(t, e, "Write", map[string]any{
		"file_path": "file.txt",
		"content":   "overwrite\n",
	})
	if !ok {
		t.Fatalf("expected success after prior read, got: %s", out)
	}
	data, _ := os.ReadFile(filepath.Join(cwd, "file.txt"))
	if string(data) != "overwrite\n" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

// TestReadBeforeWrite_FileModifiedSinceRead_Write verifies that if the file is
// modified on disk after the LLM read it, the write is rejected.
func TestReadBeforeWrite_FileModifiedSinceRead_Write(t *testing.T) {
	cwd := t.TempDir()
	filePath := filepath.Join(cwd, "file.txt")
	if err := os.WriteFile(filePath, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.txt")

	// Simulate an external process modifying the file. We nudge the mtime
	// forward to ensure the stat differs.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filePath, future, future); err != nil {
		t.Fatal(err)
	}

	out, ok := runTool(t, e, "Write", map[string]any{
		"file_path": "file.txt",
		"content":   "v2\n",
	})
	if ok {
		t.Error("expected error when file was modified since last read, got success")
	}
	if !strings.Contains(out, "changed") {
		t.Errorf("expected 'changed' in error message, got: %q", out)
	}
}

// TestReadBeforeWrite_WriteUpdatesRecord verifies that after a successful Write
// the record is refreshed so a second Write succeeds without re-reading.
func TestReadBeforeWrite_WriteUpdatesRecord(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "file.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.txt")

	out, ok := runTool(t, e, "Write", map[string]any{"file_path": "file.txt", "content": "v2\n"})
	if !ok {
		t.Fatalf("first write failed: %s", out)
	}
	out, ok = runTool(t, e, "Write", map[string]any{"file_path": "file.txt", "content": "v3\n"})
	if !ok {
		t.Fatalf("second write failed after record update: %s", out)
	}
}

func TestWrite_RejectsNullByteContent(t *testing.T) {
	e := New(t.TempDir(), t.TempDir(), t.Name())
	out, ok := runTool(t, e, "Write", map[string]any{
		"file_path": "null.txt",
		"content":   "hello\u0000world",
	})
	if ok {
		t.Fatal("expected null-byte write to fail")
	}
	if !strings.Contains(out, "null byte") {
		t.Fatalf("expected null-byte error, got: %q", out)
	}
}

// --- Edit guard tests ---

func TestReadBeforeWrite_ExistingFileWithoutRead_Edit(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "file.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	out, ok := runEdit(t, e, map[string]any{
		"file_path":  "file.txt",
		"old_string": "world",
		"new_string": "Go",
	})
	if ok {
		t.Error("expected error when editing existing file without prior read, got success")
	}
	if !strings.Contains(out, "read") {
		t.Errorf("expected 'read' hint in error message, got: %q", out)
	}
}

func TestReadBeforeWrite_ExistingFileAfterRead_Edit(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "file.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.txt")
	out, ok := runEdit(t, e, map[string]any{
		"file_path":  "file.txt",
		"old_string": "world",
		"new_string": "Go",
	})
	if !ok {
		t.Fatalf("expected success after prior read, got: %s", out)
	}
	data, _ := os.ReadFile(filepath.Join(cwd, "file.txt"))
	if string(data) != "hello Go\n" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

// TestReadBeforeWrite_FileModifiedSinceRead_Edit checks that Edit rejects a
// stale record when the file has changed since the Read tool was last called.
func TestReadBeforeWrite_FileModifiedSinceRead_Edit(t *testing.T) {
	cwd := t.TempDir()
	filePath := filepath.Join(cwd, "file.txt")
	if err := os.WriteFile(filePath, []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.txt")

	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filePath, future, future); err != nil {
		t.Fatal(err)
	}

	out, ok := runEdit(t, e, map[string]any{
		"file_path":  "file.txt",
		"old_string": "world",
		"new_string": "Go",
	})
	if ok {
		t.Error("expected error when file was modified since last read, got success")
	}
	if !strings.Contains(out, "changed") {
		t.Errorf("expected 'changed' in error message, got: %q", out)
	}
}

// TestReadBeforeWrite_EditUpdatesRecord verifies that after a successful Edit
// the record is refreshed so a second Edit succeeds without re-reading.
func TestReadBeforeWrite_EditUpdatesRecord(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "file.txt"), []byte("a b c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.txt")

	out, ok := runEdit(t, e, map[string]any{"file_path": "file.txt", "old_string": "a", "new_string": "A"})
	if !ok {
		t.Fatalf("first edit failed: %s", out)
	}
	out, ok = runEdit(t, e, map[string]any{"file_path": "file.txt", "old_string": "b", "new_string": "B"})
	if !ok {
		t.Fatalf("second edit failed after record update: %s", out)
	}
	data, _ := os.ReadFile(filepath.Join(cwd, "file.txt"))
	if string(data) != "A B c\n" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestEdit_RejectsBinarySourceFile(t *testing.T) {
	cwd := t.TempDir()
	filePath := filepath.Join(cwd, "file.bin")
	if err := os.WriteFile(filePath, []byte("hello\x00world"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.bin")
	out, ok := runEdit(t, e, map[string]any{
		"file_path":  "file.bin",
		"old_string": "hello",
		"new_string": "goodbye",
	})
	if ok {
		t.Fatal("expected binary source edit to fail")
	}
	if !strings.Contains(out, "null byte") {
		t.Fatalf("expected null-byte error, got: %q", out)
	}
}

func TestEdit_RejectsNullByteReplacement(t *testing.T) {
	cwd := t.TempDir()
	filePath := filepath.Join(cwd, "file.txt")
	if err := os.WriteFile(filePath, []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(cwd, t.TempDir(), t.Name())
	primeRead(t, e, "file.txt")
	out, ok := runEdit(t, e, map[string]any{
		"file_path":  "file.txt",
		"old_string": "world",
		"new_string": "Go\u0000",
	})
	if ok {
		t.Fatal("expected null-byte replacement to fail")
	}
	if !strings.Contains(out, "null byte") {
		t.Fatalf("expected null-byte error, got: %q", out)
	}
}
