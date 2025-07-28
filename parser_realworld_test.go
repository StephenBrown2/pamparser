package pamparser

import (
	"slices"
	"strings"
	"testing"
)

func TestParser_RealWorldIncludeExample(t *testing.T) {
	// This mimics a typical /etc/pam.d/sudo file structure
	input := `#%PAM-1.0
session    required     pam_env.so readenv=1 user_readenv=0
session    required     pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive`

	parser := NewParser()
	config, err := parser.ParseWithService(strings.NewReader(input), true, "sudo")
	if err != nil {
		t.Fatalf("Unexpected error parsing real-world example: %v", err)
	}

	// Should have 5 rules total: 2 regular rules + 3 @include directives
	expectedRuleCount := 5
	if len(config.Rules) != expectedRuleCount {
		t.Errorf("Expected %d rules, got %d", expectedRuleCount, len(config.Rules))
	}

	// Check the first rule (regular PAM rule)
	if len(config.Rules) > 0 {
		rule := config.Rules[0]
		if rule.IsDirective {
			t.Errorf("First rule should not be a directive")
		}
		if rule.Service != "sudo" {
			t.Errorf("Expected service=sudo, got %s", rule.Service)
		}
		if rule.Type != ModuleTypeSession {
			t.Errorf("Expected type=session, got %s", rule.Type)
		}
	}

	// Check the @include directives
	includeCount := 0
	expectedIncludes := []string{"common-auth", "common-account", "common-session-noninteractive"}

	for _, rule := range config.Rules {
		if rule.IsDirective && rule.DirectiveType == "include" {
			includeCount++

			// Check if this is one of the expected includes
			found := slices.Contains(expectedIncludes, rule.DirectiveTarget)
			if !found {
				t.Errorf("Unexpected include target: %s", rule.DirectiveTarget)
			}
		}
	}

	if includeCount != 3 {
		t.Errorf("Expected 3 include directives, got %d", includeCount)
	}

	t.Logf("Successfully parsed real-world PAM file with %d rules (%d includes)",
		len(config.Rules), includeCount)
}
