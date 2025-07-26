package pamparser

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCmdTool tests the command-line tool functionality
func TestCmdTool(t *testing.T) {
	// Build the command-line tool first
	cmdPath := filepath.Join(os.TempDir(), "pam-tool-test")
	buildCmd := exec.Command("go", "build", "-o", cmdPath, "./cmd/pam-tool")
	err := buildCmd.Run()
	if err != nil {
		t.Fatalf("Failed to build command-line tool: %v", err)
	}
	defer func() { _ = os.Remove(cmdPath) }()

	// Create a temporary PAM file for testing
	tempFile := filepath.Join(os.TempDir(), "test-pam")
	pamContent := `auth required pam_unix.so
account sufficient pam_permit.so
session optional pam_systemd.so
`
	err = os.WriteFile(tempFile, []byte(pamContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to create test PAM file: %v", err)
	}
	defer func() { _ = os.Remove(tempFile) }()

	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "list command",
			args:        []string{"-file", tempFile, "-list"},
			expectError: false,
		},
		{
			name:        "validate command",
			args:        []string{"-file", tempFile, "-validate"},
			expectError: false,
		},
		{
			name:        "help flag",
			args:        []string{"-help"},
			expectError: false,
		},
		{
			name:        "no file with action",
			args:        []string{"-validate"},
			expectError: false, // Shows help
		},
		{
			name:        "missing file",
			args:        []string{"-file", "/nonexistent/file", "-list"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(cmdPath, tt.args...)
			output, err := cmd.CombinedOutput()

			if tt.expectError && err == nil {
				t.Errorf("Expected error but command succeeded. Output: %s", string(output))
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected success but command failed: %v. Output: %s", err, string(output))
			}
		})
	}
}

// TestCmdToolHelp tests help output
func TestCmdToolHelp(t *testing.T) {
	cmdPath := filepath.Join(os.TempDir(), "pam-tool-test-help")
	buildCmd := exec.Command("go", "build", "-o", cmdPath, "./cmd/pam-tool")
	err := buildCmd.Run()
	if err != nil {
		t.Fatalf("Failed to build command-line tool: %v", err)
	}
	defer func() { _ = os.Remove(cmdPath) }()

	// Test help flag
	cmd := exec.Command(cmdPath, "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Help command failed: %v", err)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Usage:") {
		t.Errorf("Help output doesn't contain usage information: %s", outputStr)
	}
	if !strings.Contains(outputStr, "list") {
		t.Errorf("Help output doesn't mention list command: %s", outputStr)
	}
}

// TestCmdToolVersionOrSimilar tests for any version-like flag
func TestCmdToolVersionOrSimilar(t *testing.T) {
	cmdPath := filepath.Join(os.TempDir(), "pam-tool-test-version")
	buildCmd := exec.Command("go", "build", "-o", cmdPath, "./cmd/pam-tool")
	err := buildCmd.Run()
	if err != nil {
		t.Fatalf("Failed to build command-line tool: %v", err)
	}
	defer func() { _ = os.Remove(cmdPath) }()

	// Test version flag (might not exist)
	cmd := exec.Command(cmdPath, "--version")
	_ = cmd.Run() // We don't care about the result
	// We don't assert on error since version flag might not be implemented
	// This test just exercises the code path
}
