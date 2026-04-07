package tools

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/obot-platform/discobot/agent-go/message"
	"github.com/obot-platform/discobot/agent-go/thread"
)

type writeInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

func (e *Executor) executeWrite(call message.ToolCallPart) (thread.ToolExecuteResult, error) {
	var input writeInput
	if err := unmarshalInput(call, &input); err != nil {
		return errResult(call, err.Error()), nil
	}
	if input.FilePath == "" {
		return errResult(call, "file_path is required"), nil
	}

	path := resolvePath(e.cwd, input.FilePath)

	if err := e.checkWriteAllowed(path, input.FilePath); err != nil {
		return errResult(call, err.Error()), nil
	}
	if err := validateToolWriteTextContent(input.Content, input.FilePath); err != nil {
		return errResult(call, err.Error()), nil
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errResult(call, fmt.Sprintf("failed to create parent directory: %v", err)), nil
	}

	if err := os.WriteFile(path, []byte(input.Content), 0o644); err != nil {
		return errResult(call, fmt.Sprintf("failed to write file: %v", err)), nil
	}

	e.recordFileWritten(path)
	return textResult(call, fmt.Sprintf("Successfully wrote to %s", input.FilePath)), nil
}

func validateToolReadableTextFile(data []byte, displayPath string) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%s contains invalid UTF-8 and cannot be edited as text", displayPath)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return fmt.Errorf("%s contains a null byte and cannot be edited as text", displayPath)
	}
	return nil
}

func validateToolWriteTextContent(content string, displayPath string) error {
	if !utf8.ValidString(content) {
		return fmt.Errorf("%s content must be valid UTF-8", displayPath)
	}
	if strings.IndexByte(content, 0) >= 0 {
		return fmt.Errorf("%s content contains a null byte; binary content is not allowed", displayPath)
	}
	return nil
}
