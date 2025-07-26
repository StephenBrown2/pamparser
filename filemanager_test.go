package pamparser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileManager_NewFileManager(t *testing.T) {
	fm := NewFileManager()
	if fm == nil {
		t.Error("NewFileManager should return a non-nil FileManager")
	}
}

func TestFileManager_LoadFromString(t *testing.T) {
	fm := NewFileManager()

	configStr := `# Test configuration
auth required pam_unix.so nullok
account required pam_unix.so
`

	config, err := fm.LoadFromString(configStr, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(config.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(config.Rules))
	}

	if config.Rules[0].Type != ModuleTypeAuth {
		t.Errorf("expected first rule to be auth, got %s", config.Rules[0].Type)
	}
}

func TestFileManager_LoadFromReader(t *testing.T) {
	fm := NewFileManager()

	configStr := `auth required pam_unix.so
account required pam_unix.so
`

	reader := strings.NewReader(configStr)
	config, err := fm.LoadFromReader(reader, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(config.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(config.Rules))
	}
}

func TestFileManager_SaveToString(t *testing.T) {
	fm := NewFileManager()
	required := ControlRequired

	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
		},
		IsPamD: true,
	}

	output, err := fm.SaveToString(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "auth required pam_unix.so") {
		t.Error("output should contain the rule")
	}
}

func TestFileManager_LoadAndSaveFile(t *testing.T) {
	fm := NewFileManager()

	// Create a temporary file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pamd")

	configStr := `# Test PAM configuration
auth required pam_unix.so nullok
account required pam_unix.so
session optional pam_motd.so
`

	err := os.WriteFile(testFile, []byte(configStr), 0o644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test LoadFromFile
	config, err := fm.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("unexpected error loading file: %v", err)
	}

	if len(config.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(config.Rules))
	}

	// Test SaveToFile
	outputFile := filepath.Join(tmpDir, "output.pamd")
	err = fm.SaveToFile(config, outputFile)
	if err != nil {
		t.Fatalf("unexpected error saving file: %v", err)
	}

	// Verify the file was created and has content
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !strings.Contains(string(content), "auth required pam_unix.so") {
		t.Error("output file should contain the rules")
	}
}

func TestFileManager_BackupAndRestore(t *testing.T) {
	fm := NewFileManager()

	// Create a temporary file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pamd")

	originalContent := `auth required pam_unix.so
account required pam_unix.so
`

	err := os.WriteFile(testFile, []byte(originalContent), 0o644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test BackupFile
	backupPath, err := fm.BackupFile(testFile)
	if err != nil {
		t.Fatalf("unexpected error creating backup: %v", err)
	}

	// Verify backup exists and has correct content
	backupContent, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed to read backup file: %v", err)
	}

	if string(backupContent) != originalContent {
		t.Error("backup content doesn't match original")
	}

	// Modify the original file
	modifiedContent := `auth sufficient pam_ldap.so
account required pam_unix.so
`
	err = os.WriteFile(testFile, []byte(modifiedContent), 0o644)
	if err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	// Test RestoreFromBackup
	err = fm.RestoreFromBackup(testFile)
	if err != nil {
		t.Fatalf("unexpected error restoring backup: %v", err)
	}

	// Verify restoration
	restoredContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read restored file: %v", err)
	}

	if string(restoredContent) != originalContent {
		t.Error("restored content doesn't match original")
	}
}

func TestFileManager_ValidateFile(t *testing.T) {
	fm := NewFileManager()

	// Create a temporary file with valid content
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "valid.pamd")

	validContent := `auth required pam_unix.so
account required pam_unix.so
`

	err := os.WriteFile(validFile, []byte(validContent), 0o644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test validation
	warnings, err := fm.ValidateFile(validFile)
	if err != nil {
		t.Fatalf("unexpected error validating file: %v", err)
	}

	// Should have no warnings for valid file
	if len(warnings) > 0 {
		t.Errorf("expected no warnings for valid file, got %d", len(warnings))
	}

	// Test with non-existent file
	_, err = fm.ValidateFile("/nonexistent/file")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestFileManager_GetDefaultPaths(t *testing.T) {
	paths := GetDefaultPaths()

	if len(paths) == 0 {
		t.Error("expected at least one default path")
	}

	// Should include standard PAM paths
	if _, exists := paths["pam.conf"]; !exists {
		t.Error("default paths should include pam.conf")
	}

	if _, exists := paths["pam.d"]; !exists {
		t.Error("default paths should include pam.d")
	}

	// Check some common services
	expectedServices := []string{"login", "sshd", "sudo"}
	for _, service := range expectedServices {
		if _, exists := paths[service]; !exists {
			t.Errorf("default paths should include %s", service)
		}
	}
}

func TestFileManager_ListPamDFiles(t *testing.T) {
	// Create a temporary pam.d directory structure
	tmpDir := t.TempDir()
	pamDDir := filepath.Join(tmpDir, "pam.d")
	err := os.MkdirAll(pamDDir, 0o755)
	if err != nil {
		t.Fatalf("failed to create pam.d directory: %v", err)
	}

	// Create some test files
	testFiles := []string{"common-auth", "common-account", "sshd", "login"}
	for _, filename := range testFiles {
		filePath := filepath.Join(pamDDir, filename)
		writeErr := os.WriteFile(filePath, []byte("auth required pam_unix.so\n"), 0o644)
		if writeErr != nil {
			t.Fatalf("failed to create test file %s: %v", filename, writeErr)
		}
	}

	// Also create a subdirectory (should be ignored)
	subDir := filepath.Join(pamDDir, "subdir")
	err = os.MkdirAll(subDir, 0o755)
	if err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}

	// Test ListPamDFiles
	files, err := ListPamDFiles(pamDDir)
	if err != nil {
		t.Fatalf("unexpected error listing files: %v", err)
	}

	if len(files) != len(testFiles) {
		t.Errorf("expected %d files, got %d", len(testFiles), len(files))
	}

	// Verify all test files are included
	fileMap := make(map[string]bool)
	for _, file := range files {
		fileMap[filepath.Base(file)] = true
	}

	for _, expectedFile := range testFiles {
		if !fileMap[expectedFile] {
			t.Errorf("expected file %s not found in results", expectedFile)
		}
	}

	// Test with non-existent directory
	_, err = ListPamDFiles("/nonexistent/directory")
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestFileManager_DetectFormat(t *testing.T) {
	tmpDir := t.TempDir()

	// Test pam.conf format detection
	pamConfContent := `login auth required pam_unix.so
login account required pam_unix.so
`
	pamConfFile := filepath.Join(tmpDir, "pam.conf")
	err := os.WriteFile(pamConfFile, []byte(pamConfContent), 0o644)
	if err != nil {
		t.Fatalf("failed to create pam.conf test file: %v", err)
	}

	isPamD, err := DetectFormat(pamConfFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if isPamD {
		t.Error("should detect pam.conf format (isPamD should be false)")
	}

	// Test pam.d format detection
	pamDContent := `auth required pam_unix.so
account required pam_unix.so
`
	pamDFile := filepath.Join(tmpDir, "pam.d", "test-service")
	// Create pam.d directory
	err = os.MkdirAll(filepath.Dir(pamDFile), 0o755)
	if err != nil {
		t.Fatalf("failed to create pam.d directory: %v", err)
	}

	err = os.WriteFile(pamDFile, []byte(pamDContent), 0o644)
	if err != nil {
		t.Fatalf("failed to create pam.d test file: %v", err)
	}

	isPamD, err = DetectFormat(pamDFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !isPamD {
		// Let's see what's in the file
		content, _ := os.ReadFile(pamDFile)
		t.Errorf("should detect pam.d format (isPamD should be true). File content: %q", string(content))
	} // Test empty content
	emptyFile := filepath.Join(tmpDir, "empty")
	err = os.WriteFile(emptyFile, []byte(""), 0o644)
	if err != nil {
		t.Fatalf("failed to create empty test file: %v", err)
	}

	isPamD, err = DetectFormat(emptyFile)
	if err != nil {
		t.Fatalf("unexpected error for empty content: %v", err)
	}

	// Should default based on file path for empty content
	// Since our test file doesn't contain /pam.d/, it should default to false
	if isPamD {
		t.Error("should default to pam.conf format for empty content not in /pam.d/")
	}

	// Test non-existent file
	_, err = DetectFormat("/nonexistent/file")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestFileManager_SaveToWriter(t *testing.T) {
	fm := NewFileManager()

	config := &Config{
		Rules: []Rule{
			{
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
			},
		},
	}

	var buf strings.Builder
	err := fm.SaveToWriter(config, &buf)
	if err != nil {
		t.Fatalf("SaveToWriter failed: %v", err)
	}

	result := buf.String()
	if !strings.Contains(result, "auth required pam_unix.so") {
		t.Errorf("Expected rule not found in output: %s", result)
	}
}

func TestFileManager_ErrorPaths(t *testing.T) {
	fm := NewFileManager()

	// Test LoadFromFile with non-existent file
	_, err := fm.LoadFromFile("/nonexistent/path")
	if err == nil {
		t.Error("Expected error when loading non-existent file")
	}

	// Test SaveToFile with invalid path (assuming /invalid/path doesn't exist)
	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: ptrControlType(ControlRequired)}, ModulePath: "pam_unix.so"},
		},
	}

	err = fm.SaveToFile(config, "/invalid/nonexistent/path/file.conf")
	if err == nil {
		t.Error("Expected error when saving to invalid path")
	}

	// Test BackupFile with non-existent file
	_, err = fm.BackupFile("/nonexistent/file")
	if err == nil {
		t.Error("Expected error when backing up non-existent file")
	}

	// Test RestoreFromBackup with non-existent backup
	err = fm.RestoreFromBackup("/nonexistent/file")
	if err == nil {
		t.Error("Expected error when restoring non-existent backup")
	}
}

func TestListPamDFilesError(t *testing.T) {
	// Test with non-existent directory
	_, err := ListPamDFiles("/nonexistent/directory")
	if err == nil {
		t.Error("Expected error when listing files in non-existent directory")
	}
}

func TestDetectFormatEdgeCases(t *testing.T) {
	// Create temporary file with non-standard content
	tmpfile, err := os.CreateTemp("", "pam_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if removeErr := os.Remove(tmpfile.Name()); removeErr != nil {
			t.Logf("Failed to remove temp file: %v", removeErr)
		}
	}()

	// Write content that's not clearly pam.conf or pam.d format
	content := "# Just a comment\n# Another comment\n"
	if _, writeErr := tmpfile.Write([]byte(content)); writeErr != nil {
		t.Fatalf("Failed to write temp file: %v", writeErr)
	}
	if closeErr := tmpfile.Close(); closeErr != nil {
		t.Fatalf("Failed to close temp file: %v", closeErr)
	}

	isPamD, err := DetectFormat(tmpfile.Name())
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}
	// Should default to false when unclear
	if isPamD {
		t.Error("Expected DetectFormat to default to false for unclear content")
	}
}
