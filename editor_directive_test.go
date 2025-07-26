package pamparser

import (
	"strings"
	"testing"
)

func TestEditor_AddIncludeDirective(t *testing.T) {
	// Start with a simple config
	input := "session required pam_unix.so"

	parser := NewParser()
	config, err := parser.Parse(strings.NewReader(input), true)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	t.Logf("Initial config has %d rules", len(config.Rules))

	editor := NewEditor(config)

	// Add an include directive
	includeRule := Rule{
		IsDirective:     true,
		DirectiveType:   "include",
		DirectiveTarget: "common-auth",
		Comment:         "Authentication",
	}

	editor.AddRule(includeRule)

	updatedConfig := editor.GetConfig()
	t.Logf("After adding directive, config has %d rules", len(updatedConfig.Rules))

	// Check that the directive was added correctly
	found := false
	for i, rule := range updatedConfig.Rules {
		t.Logf("Rule %d: IsDirective=%v, Type='%s', DirectiveType='%s', DirectiveTarget='%s'",
			i, rule.IsDirective, rule.Type, rule.DirectiveType, rule.DirectiveTarget)

		if rule.IsDirective && rule.DirectiveType == "include" && rule.DirectiveTarget == "common-auth" {
			found = true
		}
	}

	if !found {
		t.Error("Include directive not found or not preserved correctly")
	}

	// Test writing
	writer := NewWriter()
	output, err := writer.WriteString(updatedConfig)
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	t.Logf("Written output:\n%s", output)

	// Should contain the include directive
	if !strings.Contains(output, "@include common-auth") {
		t.Error("Output doesn't contain expected @include directive")
	}
}
