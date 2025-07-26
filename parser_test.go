package pamparser

import (
	"strings"
	"testing"
)

func TestParser_ParseSimpleRule(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		line     string
		expected Rule
		isPamD   bool
		wantErr  bool
	}{
		{
			name:   "pam.conf format",
			line:   "login auth required pam_unix.so nullok",
			isPamD: false,
			expected: Rule{
				Service:    "login",
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
				Arguments:  []string{"nullok"},
			},
		},
		{
			name:   "pam.d format",
			line:   "auth required pam_unix.so nullok",
			isPamD: true,
			expected: Rule{
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
				Arguments:  []string{"nullok"},
			},
		},
		{
			name:   "optional control",
			line:   "auth -optional pam_unix.so",
			isPamD: true,
			expected: Rule{
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlOptional), Optional: true},
				ModulePath: "pam_unix.so",
			},
		},
		{
			name:   "with comment",
			line:   "auth required pam_unix.so # This is a comment",
			isPamD: true,
			expected: Rule{
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
				Comment:    "This is a comment",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, comment, err := parser.parseLine(tt.line, 1, tt.isPamD, "")

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if comment != "" {
				t.Errorf("Expected no comment, got: %s", comment)
				return
			}

			if rule == nil {
				t.Errorf("Expected rule but got nil")
				return
			}

			if rule.Service != tt.expected.Service {
				t.Errorf("Service: expected %s, got %s", tt.expected.Service, rule.Service)
			}

			if rule.Type != tt.expected.Type {
				t.Errorf("Type: expected %s, got %s", tt.expected.Type, rule.Type)
			}

			if rule.ModulePath != tt.expected.ModulePath {
				t.Errorf("ModulePath: expected %s, got %s", tt.expected.ModulePath, rule.ModulePath)
			}

			if rule.Comment != tt.expected.Comment {
				t.Errorf("Comment: expected %s, got %s", tt.expected.Comment, rule.Comment)
			}

			// Check arguments
			if len(rule.Arguments) != len(tt.expected.Arguments) {
				t.Errorf("Arguments length: expected %d, got %d", len(tt.expected.Arguments), len(rule.Arguments))
			} else {
				for i, arg := range rule.Arguments {
					if arg != tt.expected.Arguments[i] {
						t.Errorf("Argument %d: expected %s, got %s", i, tt.expected.Arguments[i], arg)
					}
				}
			}
		})
	}
}

func TestParser_ParseComplexControl(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name       string
		controlStr string
		expected   Control
		wantErr    bool
	}{
		{
			name:       "simple success and default",
			controlStr: "[success=ok default=bad]",
			expected: Control{
				Complex: map[ReturnValue]any{
					ReturnSuccess: ActionOK,
					ReturnDefault: ActionBad,
				},
			},
		},
		{
			name:       "with jump action",
			controlStr: "[success=done default=2]",
			expected: Control{
				Complex: map[ReturnValue]any{
					ReturnSuccess: ActionDone,
					ReturnDefault: 2,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control, err := parser.parseComplexControl(tt.controlStr, false)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(control.Complex) != len(tt.expected.Complex) {
				t.Errorf("Complex control length: expected %d, got %d", len(tt.expected.Complex), len(control.Complex))
				return
			}

			for key, expectedValue := range tt.expected.Complex {
				actualValue, exists := control.Complex[key]
				if !exists {
					t.Errorf("Missing key %s in complex control", key)
					continue
				}

				if actualValue != expectedValue {
					t.Errorf("Value for %s: expected %v, got %v", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestParser_ParseArguments(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		argStr   string
		expected []string
	}{
		{
			name:     "simple arguments",
			argStr:   "nullok try_first_pass",
			expected: []string{"nullok", "try_first_pass"},
		},
		{
			name:     "bracketed argument",
			argStr:   "user=test [query=select * from users where name='user']",
			expected: []string{"user=test", "query=select * from users where name='user'"},
		},
		{
			name:     "escaped bracket",
			argStr:   "[message=Hello \\] World]",
			expected: []string{"message=Hello ] World"},
		},
		{
			name:     "empty",
			argStr:   "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.parseArguments(tt.argStr)

			if len(result) != len(tt.expected) {
				t.Errorf("Length: expected %d, got %d", len(tt.expected), len(result))
				return
			}

			for i, arg := range result {
				if arg != tt.expected[i] {
					t.Errorf("Argument %d: expected %s, got %s", i, tt.expected[i], arg)
				}
			}
		})
	}
}

func TestParser_ParseFullConfig(t *testing.T) {
	parser := NewParser()

	pamConfContent := `# PAM configuration for login
# This is a test configuration
login auth required pam_unix.so nullok
login auth sufficient pam_ldap.so
login account required pam_unix.so
# Another comment
login session required pam_unix.so
`

	config, err := parser.Parse(strings.NewReader(pamConfContent), false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(config.Rules) != 4 {
		t.Errorf("Expected 4 rules, got %d", len(config.Rules))
	}

	if len(config.Comments) != 3 {
		t.Errorf("Expected 3 comments, got %d", len(config.Comments))
	}

	// Check first rule
	rule := config.Rules[0]
	if rule.Service != "login" {
		t.Errorf("Expected service 'login', got '%s'", rule.Service)
	}
	if rule.Type != ModuleTypeAuth {
		t.Errorf("Expected type 'auth', got '%s'", rule.Type)
	}
	if rule.Control.Simple == nil || *rule.Control.Simple != ControlRequired {
		t.Errorf("Expected control 'required'")
	}
}

func TestParser_ParsePamDConfig(t *testing.T) {
	parser := NewParser()

	pamDContent := `# PAM configuration for SSH
auth required pam_unix.so
auth sufficient pam_ldap.so
account required pam_unix.so
session required pam_unix.so
`

	config, err := parser.Parse(strings.NewReader(pamDContent), true)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(config.Rules) != 4 {
		t.Errorf("Expected 4 rules, got %d", len(config.Rules))
	}

	// Check that no rules have service field
	for i, rule := range config.Rules {
		if rule.Service != "" {
			t.Errorf("Rule %d should not have service field in pam.d format, got '%s'", i, rule.Service)
		}
	}
}

func TestParser_ParseLineContinuation(t *testing.T) {
	parser := NewParser()

	content := `auth required pam_mysql.so user=test passwd=secret \\
    db=testdb query=select user from users \\
    where name='test'
`

	config, err := parser.Parse(strings.NewReader(content), true)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(config.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(config.Rules))
	}

	rule := config.Rules[0]
	if len(rule.Arguments) < 4 {
		t.Errorf("Expected at least 4 arguments, got %d", len(rule.Arguments))
	}
}

// Helper function to create pointer to ControlType
func ptrControlType(ct ControlType) *ControlType {
	return &ct
}

func TestParser_ArgumentParsingEdgeCases(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		argStr   string
		expected []string
	}{
		{
			name:     "empty string",
			argStr:   "",
			expected: nil,
		},
		{
			name:     "only whitespace",
			argStr:   "   \t  ",
			expected: nil,
		},
		{
			name:     "unclosed bracket",
			argStr:   "[unclosed",
			expected: nil, // Should handle unclosed bracket gracefully
		},
		{
			name:     "bracket at end",
			argStr:   "arg1 [",
			expected: []string{"arg1"}, // Should parse arg1, ignore incomplete bracket
		},
		{
			name:     "escaped bracket in middle",
			argStr:   "[content with \\] bracket]",
			expected: []string{"content with ] bracket"},
		},
		{
			name:     "nested brackets",
			argStr:   "[outer [inner] content]",
			expected: []string{"outer [inner] content"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.parseArguments(tt.argStr)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d args, got %d: %v", len(tt.expected), len(result), result)
				return
			}
			for i, exp := range tt.expected {
				if i < len(result) && result[i] != exp {
					t.Errorf("Arg %d: expected %q, got %q", i, exp, result[i])
				}
			}
		})
	}
}

func TestParser_DirectiveEdgeCases(t *testing.T) {
	parser := NewParser()

	// Test empty directive
	_, _, err := parser.parseDirective([]string{}, &Rule{}, 1)
	if err == nil {
		t.Error("Expected error for empty directive")
	}

	// Test directive without @ prefix
	_, _, err = parser.parseDirective([]string{"include", "common-auth"}, &Rule{}, 1)
	if err == nil {
		t.Error("Expected error for directive without @ prefix")
	}

	// Test unknown directive
	_, _, err = parser.parseDirective([]string{"@unknown", "target"}, &Rule{}, 1)
	if err == nil {
		t.Error("Expected error for unknown directive")
	}

	// Test @include without target
	_, _, err = parser.parseDirective([]string{"@include"}, &Rule{}, 1)
	if err == nil {
		t.Error("Expected error for @include without target")
	}
}

func TestParser_TokenizeLineEdgeCases(t *testing.T) {
	// Since tokenizeLine is not public, test through parseLine instead
	parser := NewParser()

	// Test line with only comment - should be handled by parseLine
	_, comment, err := parser.parseLine("# only comment", 1, false, "")
	if err != nil {
		t.Fatalf("parseLine failed: %v", err)
	}
	if comment != "only comment" {
		t.Errorf("Expected comment 'only comment', got '%s'", comment)
	}
}

func TestParser_NegativeModuleTypes(t *testing.T) {
	parser := NewParser()

	// Test negative module type (-session)
	content := `-session optional pam_systemd.so`
	config, err := parser.ParseWithService(strings.NewReader(content), true, "test")
	if err != nil {
		t.Fatalf("Failed to parse negative module type: %v", err)
	}

	if len(config.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(config.Rules))
	}

	rule := config.Rules[0]
	if rule.Type != "-session" {
		t.Errorf("Expected type '-session', got '%s'", rule.Type)
	}

	// Test that IsValidModuleType accepts negative types
	validTypes := []string{"-session", "-auth", "-account", "-password", "-session-noninteractive"}
	for _, moduleType := range validTypes {
		if !IsValidModuleType(moduleType) {
			t.Errorf("Expected %s to be valid", moduleType)
		}
	}

	// Test that IsValidModuleType accepts session-noninteractive
	if !IsValidModuleType("session-noninteractive") {
		t.Error("Expected session-noninteractive to be valid")
	}

	// Test session-noninteractive module type
	sessionNoninteractiveContent := `session-noninteractive required pam_systemd.so`
	config, err = parser.ParseWithService(strings.NewReader(sessionNoninteractiveContent), true, "test")
	if err != nil {
		t.Fatalf("Failed to parse session-noninteractive module type: %v", err)
	}

	if len(config.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(config.Rules))
	}

	rule = config.Rules[0]
	if rule.Type != "session-noninteractive" {
		t.Errorf("Expected type 'session-noninteractive', got '%s'", rule.Type)
	}

	// Test negative session-noninteractive module type
	negativeSessionNoninteractiveContent := `-session-noninteractive optional pam_systemd.so`
	config, err = parser.ParseWithService(strings.NewReader(negativeSessionNoninteractiveContent), true, "test")
	if err != nil {
		t.Fatalf("Failed to parse negative session-noninteractive module type: %v", err)
	}

	if len(config.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(config.Rules))
	}

	rule = config.Rules[0]
	if rule.Type != "-session-noninteractive" {
		t.Errorf("Expected type '-session-noninteractive', got '%s'", rule.Type)
	}

	// Test GetModuleTypeOrder with negative types
	order := GetModuleTypeOrder("-session")
	expectedOrder := GetModuleTypeOrder("session")
	if order != expectedOrder {
		t.Errorf("Expected -session to have same order as session (%d), got %d", expectedOrder, order)
	}

	// Test that session-noninteractive comes after session in ordering
	sessionOrder := GetModuleTypeOrder("session")
	sessionNoninteractiveOrder := GetModuleTypeOrder("session-noninteractive")
	if sessionNoninteractiveOrder <= sessionOrder {
		t.Errorf("Expected session-noninteractive order (%d) to be greater than session order (%d)", sessionNoninteractiveOrder, sessionOrder)
	}

	// Test that negative session-noninteractive has same order as positive
	negativeSessionNoninteractiveOrder := GetModuleTypeOrder("-session-noninteractive")
	if negativeSessionNoninteractiveOrder != sessionNoninteractiveOrder {
		t.Errorf("Expected -session-noninteractive to have same order as session-noninteractive (%d), got %d", sessionNoninteractiveOrder, negativeSessionNoninteractiveOrder)
	}
}

func TestParser_ParseWithServiceEdgeCases(t *testing.T) {
	parser := NewParser()

	// Test with empty service - use pam.conf format: service type control module
	config, err := parser.ParseWithService(strings.NewReader("testservice account required pam_unix.so"), false, "")
	if err != nil {
		t.Fatalf("ParseWithService failed: %v", err)
	}

	// Service should be read from content in non-pam.d mode
	if len(config.Rules) > 0 && config.Rules[0].Service != "testservice" {
		t.Errorf("Expected service 'testservice' from content, got '%s'", config.Rules[0].Service)
	}

	// Test with service in pam.d mode - use pam.d format: type control module
	config, err = parser.ParseWithService(strings.NewReader("account required pam_unix.so"), true, "sshd")
	if err != nil {
		t.Fatalf("ParseWithService failed: %v", err)
	}

	if len(config.Rules) > 0 && config.Rules[0].Service != "sshd" {
		t.Errorf("Expected service 'sshd', got '%s'", config.Rules[0].Service)
	}
}
