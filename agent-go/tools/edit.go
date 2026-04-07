package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/obot-platform/discobot/agent-go/message"
	"github.com/obot-platform/discobot/agent-go/thread"
)

type editInput struct {
	FilePath   string `json:"file_path"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`
}

func (e *Executor) executeEdit(call message.ToolCallPart) (thread.ToolExecuteResult, error) {
	var input editInput
	if err := unmarshalInput(call, &input); err != nil {
		return errResult(call, err.Error()), nil
	}
	if input.FilePath == "" {
		return errResult(call, "file_path is required"), nil
	}
	if input.OldString == "" {
		return errResult(call, "old_string is required"), nil
	}

	path := resolvePath(e.cwd, input.FilePath)

	// Read the file. If it doesn't exist and old_string is empty, create it.
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return errResult(call, fmt.Sprintf("file not found: %s", input.FilePath)), nil
		}
		return errResult(call, err.Error()), nil
	}

	if err := validateToolReadableTextFile(data, input.FilePath); err != nil {
		return errResult(call, err.Error()), nil
	}
	if err := validateToolWriteTextContent(input.NewString, input.FilePath); err != nil {
		return errResult(call, err.Error()), nil
	}

	content := string(data)

	// Count occurrences to provide useful feedback.
	count := strings.Count(content, input.OldString)
	if count == 0 {
		return errResult(call, fmt.Sprintf("old_string not found in %s.\n\nThe old_string must match the file content exactly, including whitespace and indentation.", input.FilePath)), nil
	}

	if count > 1 && !input.ReplaceAll {
		return errResult(call, fmt.Sprintf(
			"old_string appears %d times in %s. Use replace_all: true to replace all occurrences, or provide more context to make it unique.",
			count, input.FilePath,
		)), nil
	}

	var newContent string
	if input.ReplaceAll {
		newContent = strings.ReplaceAll(content, input.OldString, input.NewString)
	} else {
		newContent = strings.Replace(content, input.OldString, input.NewString, 1)
	}
	if err := validateToolWriteTextContent(newContent, input.FilePath); err != nil {
		return errResult(call, err.Error()), nil
	}

	// Ensure parent directory exists (in case old_string created empty file scenario).
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errResult(call, fmt.Sprintf("failed to create parent directory: %v", err)), nil
	}

	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		return errResult(call, fmt.Sprintf("failed to write file: %v", err)), nil
	}

	e.recordFileWritten(path)

	if input.ReplaceAll && count > 1 {
		return textResult(call, fmt.Sprintf("Successfully replaced %d occurrences in %s", count, input.FilePath)), nil
	}
	return textResult(call, fmt.Sprintf("Successfully edited %s", input.FilePath)), nil
}
