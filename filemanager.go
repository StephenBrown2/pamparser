package pamparser

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileManager handles file I/O operations for PAM configurations
type FileManager struct {
	parser *Parser
	writer *Writer
}

// NewFileManager creates a new file manager
func NewFileManager() *FileManager {
	return &FileManager{
		parser: NewParser(),
		writer: NewWriter(),
	}
}

// LoadFromFile loads a PAM configuration from a file
func (fm *FileManager) LoadFromFile(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	// Determine if this is a pam.d format file
	isPamD := strings.Contains(filePath, "/pam.d/") ||
		(!strings.HasSuffix(filePath, "pam.conf") && filepath.Dir(filePath) != "/etc")

	// Extract service name for pam.d format files
	var serviceName string
	if strings.Contains(filePath, "/pam.d/") {
		// Extract service name from /path/to/pam.d/servicename
		basename := filepath.Base(filePath)
		serviceName = basename
	}

	config, err := fm.parser.ParseWithService(file, isPamD, serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", filePath, err)
	}

	config.FilePath = filePath
	return config, nil
}

// LoadFromReader loads a PAM configuration from a reader
func (fm *FileManager) LoadFromReader(reader io.Reader, isPamD bool) (*Config, error) {
	return fm.parser.Parse(reader, isPamD)
}

// LoadFromString loads a PAM configuration from a string
func (fm *FileManager) LoadFromString(content string, isPamD bool) (*Config, error) {
	return fm.parser.Parse(strings.NewReader(content), isPamD)
}

// SaveToFile saves a PAM configuration to a file
func (fm *FileManager) SaveToFile(config *Config, filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	return fm.writer.Write(config, file)
}

// SaveToWriter saves a PAM configuration to a writer
func (fm *FileManager) SaveToWriter(config *Config, writer io.Writer) error {
	return fm.writer.Write(config, writer)
}

// SaveToString saves a PAM configuration to a string
func (fm *FileManager) SaveToString(config *Config) (string, error) {
	return fm.writer.WriteString(config)
}

// BackupFile creates a backup of the specified file
func (fm *FileManager) BackupFile(filePath string) (string, error) {
	backupPath := filePath + ".backup"

	// Check if original file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("original file %s does not exist", filePath)
	}

	// Copy file
	src, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	_, err = io.Copy(dst, src)
	if err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	return backupPath, nil
}

// RestoreFromBackup restores a file from its backup
func (fm *FileManager) RestoreFromBackup(filePath string) error {
	backupPath := filePath + ".backup"

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file %s does not exist", backupPath)
	}

	// Copy backup to original
	src, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create original file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	_, err = io.Copy(dst, src)
	if err != nil {
		return fmt.Errorf("failed to copy backup: %w", err)
	}

	return nil
}

// ValidateFile validates a PAM configuration file syntax
func (fm *FileManager) ValidateFile(filePath string) ([]string, error) {
	config, err := fm.LoadFromFile(filePath)
	if err != nil {
		return nil, err
	}

	editor := NewEditor(config)
	return editor.Validate(), nil
}

// GetDefaultPaths returns common PAM configuration file paths
func GetDefaultPaths() map[string]string {
	return map[string]string{
		"pam.conf":        "/etc/pam.conf",
		"pam.d":           "/etc/pam.d",
		"common-account":  "/etc/pam.d/common-account",
		"common-auth":     "/etc/pam.d/common-auth",
		"common-password": "/etc/pam.d/common-password",
		"common-session":  "/etc/pam.d/common-session",
		"login":           "/etc/pam.d/login",
		"sshd":            "/etc/pam.d/sshd",
		"sudo":            "/etc/pam.d/sudo",
		"su":              "/etc/pam.d/su",
	}
}

// ListPamDFiles lists all files in the /etc/pam.d directory
func ListPamDFiles(pamDDir string) ([]string, error) {
	if pamDDir == "" {
		pamDDir = "/etc/pam.d"
	}

	entries, err := os.ReadDir(pamDDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read pam.d directory %s: %w", pamDDir, err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(pamDDir, entry.Name()))
		}
	}

	return files, nil
}

// DetectFormat detects whether a file uses pam.conf or pam.d format
func DetectFormat(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	// Read a few lines to detect format
	buffer := make([]byte, 1024)
	n, err := file.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("failed to read file: %w", err)
	}

	content := string(buffer[:n])
	lines := strings.Split(content, "\n")

	// Count fields in non-comment, non-empty lines
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			// Check if the first field looks like a service name
			// In pam.d format, first field should be module type
			if IsValidModuleType(fields[0]) {
				return true, nil // pam.d format
			}
			return false, nil // pam.conf format
		}
	}

	// Default assumption based on file path
	return strings.Contains(filePath, "/pam.d/"), nil
}
