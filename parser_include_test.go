package pamparser

import (
	"strings"
	"testing"
)

func TestParser_ParseIncludeDirective(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		description string
		shouldError bool
	}{
		{
			name:        "include directive",
			input:       "@include common-auth",
			shouldError: false,
			description: "Should parse @include directive correctly",
		},
		{
			name:        "include directive with comment",
			input:       "@include common-auth # Include common authentication",
			shouldError: false,
			description: "Should parse @include directive with comment",
		},
		{
			name: "multiple include directives",
			input: `@include common-auth
@include common-account
@include common-session`,
			shouldError: false,
			description: "Should parse multiple include directives",
		},
		{
			name: "mixed rules and includes",
			input: `auth required pam_unix.so
@include common-auth
account required pam_unix.so`,
			shouldError: false,
			description: "Should handle mixed regular rules and include directives",
		},
	}

	parser := NewParser()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := strings.NewReader(tc.input)
			config, err := parser.Parse(reader, true)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Look for include directives in the parsed rules
			hasInclude := false
			for _, rule := range config.Rules {
				if rule.IsDirective && rule.DirectiveType == "include" {
					hasInclude = true

					// Verify the directive was parsed correctly
					if rule.DirectiveTarget == "" {
						t.Errorf("Include directive missing target")
					}

					t.Logf("Found include directive: target=%s, comment=%s",
						rule.DirectiveTarget, rule.Comment)
					break
				}
			}

			if !hasInclude && strings.Contains(tc.input, "@include") {
				t.Errorf("Expected to find @include directive but didn't find one")
				t.Logf("Parsed %d rules:", len(config.Rules))
				for i, rule := range config.Rules {
					t.Logf("  Rule %d: IsDirective=%v, Type=%s, ModulePath=%s",
						i, rule.IsDirective, rule.Type, rule.ModulePath)
				}
			}
		})
	}
}
