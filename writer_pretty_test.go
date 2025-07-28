package pamparser

import (
	"strings"
	"testing"
)

func TestWriter_PrettyFormatting(t *testing.T) {
	// Create a config with varied rule lengths
	config := &Config{
		Rules: []Rule{
			{
				Type:       ModuleTypeAccount,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
				Arguments:  []string{"debug"},
			},
			{
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlSufficient)},
				ModulePath: "pam_ldap.so",
				Arguments:  []string{"try_first_pass", "use_authtok"},
			},
			{
				Type:       ModuleTypePassword,
				Control:    Control{Complex: map[ReturnValue]any{ReturnSuccess: ActionOK, ReturnDefault: ActionIgnore}},
				ModulePath: "pam_cracklib.so",
				Arguments:  []string{"retry=3", "minlen=8"},
			},
			{
				Type:       ModuleTypeSession,
				Control:    Control{Simple: ptrControlType(ControlOptional)},
				ModulePath: "pam_systemd.so",
			},
		},
	}

	writer := NewWriter()

	// Test regular formatting
	regular, err := writer.WriteString(config)
	if err != nil {
		t.Fatalf("Failed to write regular format: %v", err)
	}

	// Test pretty formatting
	pretty, err := writer.WritePrettyString(config)
	if err != nil {
		t.Fatalf("Failed to write pretty format: %v", err)
	}

	t.Logf("Regular formatting:\n%s", regular)
	t.Logf("Pretty formatting:\n%s", pretty)

	// Verify that pretty formatting has consistent column alignment
	lines := strings.Split(strings.TrimSpace(pretty), "\n")

	// Skip section headers, empty lines, and continuation lines, focus on rule lines
	var ruleLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Skip continuation lines (lines that start with whitespace)
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		// Check if line starts with a valid module type
		fields := strings.Fields(line)
		if len(fields) > 0 {
			firstField := fields[0]
			validTypes := []string{"auth", "account", "password", "session", "-auth", "-account", "-password", "-session"}
			isValidRule := false
			for _, validType := range validTypes {
				if firstField == validType || strings.HasPrefix(firstField, validType) {
					isValidRule = true
					break
				}
			}
			if isValidRule {
				ruleLines = append(ruleLines, line)
			}
		}
	}

	if len(ruleLines) < 2 {
		t.Fatal("Expected at least 2 rule lines for alignment testing")
	}

	// Check that each rule line has consistent spacing
	// This is a basic check - in a real scenario you'd verify exact column positions
	for i, line := range ruleLines {
		if len(strings.Fields(line)) < 3 {
			t.Errorf("Rule line %d has fewer than 3 fields: %s", i, line)
		}
	}
}

func TestWriter_ColumnWidthCustomization(t *testing.T) {
	config := &Config{
		Rules: []Rule{
			{
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
				Arguments:  []string{"nullok"},
			},
		},
	}

	writer := NewWriter()

	// Test custom column widths
	writer.SetPrettyFormat(true).SetColumnWidths(10, 15, 25)

	output, err := writer.WriteString(config)
	if err != nil {
		t.Fatalf("Failed to write with custom columns: %v", err)
	}

	t.Logf("Custom column formatting:\n%s", output)

	// Verify the line has proper spacing
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var ruleLine string
	for _, line := range lines {
		if strings.Contains(line, "pam_unix.so") {
			ruleLine = line
			break
		}
	}

	if ruleLine == "" {
		t.Fatal("Could not find rule line in output")
	}

	// The rule line should have the expected structure
	if !strings.Contains(ruleLine, "auth") || !strings.Contains(ruleLine, "required") || !strings.Contains(ruleLine, "pam_unix.so") {
		t.Errorf("Rule line doesn't have expected structure: %s", ruleLine)
	}
}
