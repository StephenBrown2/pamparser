package pamparser

import (
	"strings"
	"testing"
)

func TestWriter_FormatIncludeDirective(t *testing.T) {
	testCases := []struct {
		name     string
		expected string
		rule     Rule
	}{
		{
			name: "simple include directive",
			rule: Rule{
				IsDirective:     true,
				DirectiveType:   "include",
				DirectiveTarget: "common-auth",
				LineNumber:      1,
			},
			expected: "@include common-auth",
		},
		{
			name: "include directive with comment",
			rule: Rule{
				IsDirective:     true,
				DirectiveType:   "include",
				DirectiveTarget: "common-auth",
				Comment:         "Include common authentication",
				LineNumber:      1,
			},
			expected: "@include common-auth # Include common authentication",
		},
		{
			name: "include directive with arguments",
			rule: Rule{
				IsDirective:     true,
				DirectiveType:   "include",
				DirectiveTarget: "common-auth",
				Arguments:       []string{"arg1", "arg2"},
				LineNumber:      1,
			},
			expected: "@include common-auth arg1 arg2",
		},
	}

	writer := NewWriter()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := writer.formatRule(tc.rule)
			if result != tc.expected {
				t.Errorf("Expected: %s\nGot: %s", tc.expected, result)
			}
		})
	}
}

func TestWriter_RoundTripIncludeDirective(t *testing.T) {
	// Test parsing and then writing back to ensure consistency
	input := `@include common-auth
@include common-account # Account management
session required pam_unix.so`

	parser := NewParser()
	config, err := parser.Parse(strings.NewReader(input), true)
	if err != nil {
		t.Fatalf("Failed to parse input: %v", err)
	}

	writer := NewWriter()
	output, err := writer.WriteString(config)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	t.Logf("Input:\n%s", input)
	t.Logf("Output:\n%s", output)

	// Parse the output again to verify it's valid
	config2, err := parser.Parse(strings.NewReader(output), true)
	if err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	// Should have same number of rules
	if len(config.Rules) != len(config2.Rules) {
		t.Errorf("Rule count mismatch: original=%d, roundtrip=%d",
			len(config.Rules), len(config2.Rules))
	}

	// Check that include directives are preserved
	includeCount := 0
	for _, rule := range config2.Rules {
		if rule.IsDirective && rule.DirectiveType == "include" {
			includeCount++
		}
	}

	if includeCount != 2 {
		t.Errorf("Expected 2 include directives after round trip, got %d", includeCount)
	}
}
