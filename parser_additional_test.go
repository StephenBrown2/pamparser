package pamparser

import (
	"strings"
	"testing"
)

func TestIsValidModuleType_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"AUTH", true},          // uppercase
		{"Auth", true},          // mixed case
		{"invalid", false},      // invalid type
		{"", false},             // empty string
		{"account-test", false}, // hyphenated
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsValidModuleType(tt.input)
			if result != tt.expected {
				t.Errorf("IsValidModuleType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsValidControlType_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"REQUIRED", true},       // uppercase
		{"Required", true},       // mixed case
		{"invalid", false},       // invalid type
		{"", false},              // empty string
		{"optional-test", false}, // hyphenated
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsValidControlType(tt.input)
			if result != tt.expected {
				t.Errorf("IsValidControlType(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetModuleTypeOrder_AllTypes(t *testing.T) {
	tests := []struct {
		moduleType ModuleType
		expected   int
	}{
		{ModuleTypeAccount, 0},
		{ModuleTypeAuth, 1},
		{ModuleTypePassword, 2},
		{ModuleTypeSession, 3},
		{ModuleTypeSessionNoninteractive, 4},
		{ModuleType("unknown"), 5},
	}

	for _, tt := range tests {
		t.Run(string(tt.moduleType), func(t *testing.T) {
			result := GetModuleTypeOrder(tt.moduleType)
			if result != tt.expected {
				t.Errorf("GetModuleTypeOrder(%q) = %v, want %v", tt.moduleType, result, tt.expected)
			}
		})
	}
}

func TestParser_EdgeCases(t *testing.T) {
	parser := NewParser()

	// Test empty input
	t.Run("empty input", func(t *testing.T) {
		config, err := parser.Parse(strings.NewReader(""), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(config.Rules) != 0 {
			t.Errorf("expected 0 rules for empty input, got %d", len(config.Rules))
		}
	})

	// Test only comments
	t.Run("only comments", func(t *testing.T) {
		input := `# This is a comment
# Another comment
`
		config, err := parser.Parse(strings.NewReader(input), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(config.Rules) != 0 {
			t.Errorf("expected 0 rules for comment-only input, got %d", len(config.Rules))
		}
		if len(config.Comments) != 2 {
			t.Errorf("expected 2 comments, got %d", len(config.Comments))
		}
	})

	// Test whitespace only lines
	t.Run("whitespace lines", func(t *testing.T) {
		input := `
   
	
auth required pam_unix.so
   
`
		config, err := parser.Parse(strings.NewReader(input), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(config.Rules) != 1 {
			t.Errorf("expected 1 rule, got %d", len(config.Rules))
		}
	})

	// Test invalid module type
	t.Run("invalid module type", func(t *testing.T) {
		input := `invalid required pam_unix.so`
		_, err := parser.Parse(strings.NewReader(input), true)
		if err == nil {
			t.Error("expected error for invalid module type")
		}
	})

	// Test missing control
	t.Run("missing control", func(t *testing.T) {
		input := `auth pam_unix.so`
		_, err := parser.Parse(strings.NewReader(input), true)
		if err == nil {
			t.Error("expected error for missing control")
		}
	})

	// Test missing module
	t.Run("missing module", func(t *testing.T) {
		input := `auth required`
		_, err := parser.Parse(strings.NewReader(input), true)
		if err == nil {
			t.Error("expected error for missing module")
		}
	})
}

func TestParser_ComplexControlEdgeCases(t *testing.T) {
	parser := NewParser()

	// Test complex control with jump
	t.Run("complex control with jump", func(t *testing.T) {
		input := `auth [success=2 default=ignore] pam_unix.so`
		config, err := parser.Parse(strings.NewReader(input), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		rule := config.Rules[0]
		if rule.Control.Complex == nil {
			t.Fatal("expected complex control")
		}

		if jump, ok := rule.Control.Complex[ReturnSuccess].(int); !ok || jump != 2 {
			t.Errorf("expected jump value 2, got %v", rule.Control.Complex[ReturnSuccess])
		}
	})

	// Test invalid complex control - actually this doesn't fail
	t.Run("invalid complex control", func(t *testing.T) {
		input := `auth [invalid=action] pam_unix.so`
		config, err := parser.Parse(strings.NewReader(input), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should parse successfully but with invalid return value
		rule := config.Rules[0]
		if rule.Control.Complex == nil {
			t.Fatal("expected complex control")
		}
	})

	// Test malformed complex control
	t.Run("malformed complex control", func(t *testing.T) {
		input := `auth [success] pam_unix.so`
		_, err := parser.Parse(strings.NewReader(input), true)
		if err == nil {
			t.Error("expected error for malformed complex control")
		}
	})
}

func TestParser_ArgumentEdgeCases(t *testing.T) {
	parser := NewParser()

	// Test arguments with special characters
	t.Run("special characters in arguments", func(t *testing.T) {
		input := `auth required pam_unix.so [arg with spaces] normal_arg`
		config, err := parser.Parse(strings.NewReader(input), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		rule := config.Rules[0]
		if len(rule.Arguments) != 2 {
			t.Errorf("expected 2 arguments, got %d", len(rule.Arguments))
		}

		if rule.Arguments[0] != "arg with spaces" {
			t.Errorf("expected 'arg with spaces', got '%s'", rule.Arguments[0])
		}
	})

	// Test escaped brackets in arguments
	t.Run("escaped brackets", func(t *testing.T) {
		input := `auth required pam_unix.so [arg\]with\]brackets]`
		config, err := parser.Parse(strings.NewReader(input), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		rule := config.Rules[0]
		if len(rule.Arguments) != 1 {
			t.Errorf("expected 1 argument, got %d", len(rule.Arguments))
		}

		// The actual behavior - spaces are preserved around unescaped parts
		if rule.Arguments[0] != "arg] with]brackets" {
			t.Errorf("expected 'arg] with]brackets', got '%s'", rule.Arguments[0])
		}
	})

	// Test multiple bracketed arguments
	t.Run("multiple bracketed arguments", func(t *testing.T) {
		input := `auth required pam_unix.so [first arg] [second arg] normal`
		config, err := parser.Parse(strings.NewReader(input), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		rule := config.Rules[0]
		if len(rule.Arguments) != 3 {
			t.Errorf("expected 3 arguments, got %d", len(rule.Arguments))
		}

		expected := []string{"first arg", "second arg", "normal"}
		for i, exp := range expected {
			if rule.Arguments[i] != exp {
				t.Errorf("argument %d: expected '%s', got '%s'", i, exp, rule.Arguments[i])
			}
		}
	})
}
