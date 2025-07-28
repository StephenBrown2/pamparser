package pamparser

import (
	"slices"
	"strings"
	"testing"
)

func TestEditor_FindRules(t *testing.T) {
	config := &Config{
		Rules: []Rule{
			{Service: "login", Type: ModuleTypeAuth, ModulePath: "pam_unix.so"},
			{Service: "login", Type: ModuleTypeAccount, ModulePath: "pam_unix.so"},
			{Service: "sshd", Type: ModuleTypeAuth, ModulePath: "pam_unix.so"},
			{Service: "sshd", Type: ModuleTypeAuth, ModulePath: "pam_ldap.so"},
		},
	}

	editor := NewEditor(config)

	// Test service filter
	loginRules := editor.FindRules(FilterByService("login"))
	if len(loginRules) != 2 {
		t.Errorf("Expected 2 login rules, got %d", len(loginRules))
	}

	// Test type filter
	authRules := editor.FindRules(FilterByType(ModuleTypeAuth))
	if len(authRules) != 3 {
		t.Errorf("Expected 3 auth rules, got %d", len(authRules))
	}

	// Test module path filter
	ldapRules := editor.FindRules(FilterByModulePath("ldap"))
	if len(ldapRules) != 1 {
		t.Errorf("Expected 1 ldap rule, got %d", len(ldapRules))
	}

	// Test combined filters
	sshdAuthRules := editor.FindRules(CombineFilters(
		FilterByService("sshd"),
		FilterByType(ModuleTypeAuth),
	))
	if len(sshdAuthRules) != 2 {
		t.Errorf("Expected 2 sshd auth rules, got %d", len(sshdAuthRules))
	}
}

func TestEditor_AddRule(t *testing.T) {
	config := &Config{}
	editor := NewEditor(config)

	// Add rules in mixed order to test grouping
	sessionRule := Rule{
		Service:    "test",
		Type:       ModuleTypeSession,
		Control:    Control{Simple: ptrControlType(ControlRequired)},
		ModulePath: "pam_unix.so",
	}

	authRule := Rule{
		Service:    "test",
		Type:       ModuleTypeAuth,
		Control:    Control{Simple: ptrControlType(ControlRequired)},
		ModulePath: "pam_unix.so",
	}

	accountRule := Rule{
		Service:    "test",
		Type:       ModuleTypeAccount,
		Control:    Control{Simple: ptrControlType(ControlRequired)},
		ModulePath: "pam_unix.so",
	}

	// Add in reverse order
	editor.AddRule(sessionRule)
	editor.AddRule(authRule)
	editor.AddRule(accountRule)

	if len(config.Rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(config.Rules))
	}

	// Check that rules are in correct order: account, auth, session
	expectedOrder := []ModuleType{ModuleTypeAccount, ModuleTypeAuth, ModuleTypeSession}
	for i, expectedType := range expectedOrder {
		if config.Rules[i].Type != expectedType {
			t.Errorf("Rule %d: expected type %s, got %s", i, expectedType, config.Rules[i].Type)
		}
	}
}

func TestEditor_SortRulesByType(t *testing.T) {
	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeSession, Service: "test1"},
			{Type: ModuleTypeAuth, Service: "test2"},
			{Type: ModuleTypePassword, Service: "test3"},
			{Type: ModuleTypeAccount, Service: "test4"},
			{Type: ModuleTypeAuth, Service: "test5"}, // Second auth rule
		},
	}

	editor := NewEditor(config)
	editor.SortRulesByType()

	// Check that rules are now in correct order
	expectedOrder := []ModuleType{
		ModuleTypeAccount,
		ModuleTypeAuth,
		ModuleTypeAuth,
		ModuleTypePassword,
		ModuleTypeSession,
	}

	if len(config.Rules) != len(expectedOrder) {
		t.Errorf("Expected %d rules, got %d", len(expectedOrder), len(config.Rules))
	}

	for i, expectedType := range expectedOrder {
		if config.Rules[i].Type != expectedType {
			t.Errorf("Rule %d: expected type %s, got %s", i, expectedType, config.Rules[i].Type)
		}
	}

	// Check that relative order within type is preserved
	if config.Rules[1].Service != "test2" || config.Rules[2].Service != "test5" {
		t.Errorf("Relative order within auth type not preserved")
	}
}

func TestEditor_RemoveRule(t *testing.T) {
	config := &Config{
		Rules: []Rule{
			{Service: "test1", Type: ModuleTypeAuth},
			{Service: "test2", Type: ModuleTypeAuth},
			{Service: "test3", Type: ModuleTypeAuth},
		},
	}

	editor := NewEditor(config)

	err := editor.RemoveRule(1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(config.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(config.Rules))
	}

	if config.Rules[0].Service != "test1" || config.Rules[1].Service != "test3" {
		t.Errorf("Wrong rules remained after removal")
	}
}

func TestEditor_UpdateArgument(t *testing.T) {
	config := &Config{
		Rules: []Rule{
			{
				Service:   "test",
				Type:      ModuleTypeAuth,
				Arguments: []string{"nullok", "debug"},
			},
		},
	}

	editor := NewEditor(config)

	// Update existing argument
	err := editor.UpdateArgument(0, "debug", "info")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Add new argument
	err = editor.UpdateArgument(0, "timeout", "30")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	rule := config.Rules[0]
	if len(rule.Arguments) != 3 {
		t.Errorf("Expected 3 arguments, got %d", len(rule.Arguments))
	}

	// Check that timeout was added
	found := slices.Contains(rule.Arguments, "timeout=30")
	if !found {
		t.Errorf("timeout=30 argument not found")
	}
}

func TestEditor_Validate(t *testing.T) {
	config := &Config{
		IsPamD: true,
		Rules: []Rule{
			{
				// Valid rule
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
			},
			{
				// Invalid - missing module path
				Type:    ModuleTypeAuth,
				Control: Control{Simple: ptrControlType(ControlRequired)},
			},
			{
				// Invalid - has service in pam.d format (but will be accepted since it can be auto-extracted)
				Service:    "test",
				Type:       ModuleTypeAuth,
				Control:    Control{Simple: ptrControlType(ControlRequired)},
				ModulePath: "pam_unix.so",
			},
		},
	}

	editor := NewEditor(config)
	warnings := editor.Validate()

	if len(warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d: %v", len(warnings), warnings)
	}
}

func TestEditor_ValidateDirectives(t *testing.T) {
	tests := []struct {
		config      *Config
		name        string
		description string
		expectedLen int
	}{
		{
			name: "directive missing type",
			config: &Config{
				Rules: []Rule{
					{
						IsDirective:     true,
						DirectiveTarget: "common-auth",
					},
				},
			},
			expectedLen: 1,
			description: "should warn about missing directive type",
		},
		{
			name: "include directive missing target",
			config: &Config{
				Rules: []Rule{
					{
						IsDirective:   true,
						DirectiveType: "include",
					},
				},
			},
			expectedLen: 1,
			description: "should warn about missing include target",
		},
		{
			name: "valid include directive",
			config: &Config{
				Rules: []Rule{
					{
						IsDirective:     true,
						DirectiveType:   "include",
						DirectiveTarget: "common-auth",
					},
				},
			},
			expectedLen: 0,
			description: "should have no warnings for valid directive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			editor := NewEditor(tt.config)
			warnings := editor.Validate()

			if len(warnings) != tt.expectedLen {
				t.Errorf("%s: expected %d warnings, got %d: %v",
					tt.description, tt.expectedLen, len(warnings), warnings)
			}
		})
	}
}

// Helper function for string pointer
func stringPtr(s string) *ControlType {
	ct := ControlType(s)
	return &ct
}

func TestEditor_ValidateDetailedChecks(t *testing.T) {
	tests := []struct {
		config         *Config
		name           string
		expectedSubstr string
		description    string
		minWarnings    int
	}{
		{
			name: "missing module type",
			config: &Config{
				Rules: []Rule{
					{
						Control:    Control{Simple: ptrControlType(ControlRequired)},
						ModulePath: "pam_unix.so",
					},
				},
			},
			minWarnings:    1,
			expectedSubstr: "missing module type",
			description:    "should warn about missing module type",
		},
		{
			name: "missing module path",
			config: &Config{
				Rules: []Rule{
					{
						Type:    ModuleTypeAuth,
						Control: Control{Simple: ptrControlType(ControlRequired)},
					},
				},
			},
			minWarnings:    1,
			expectedSubstr: "missing module path",
			description:    "should warn about missing module path",
		},
		{
			name: "invalid module type",
			config: &Config{
				Rules: []Rule{
					{
						Type:       "invalid",
						Control:    Control{Simple: ptrControlType(ControlRequired)},
						ModulePath: "pam_unix.so",
					},
				},
			},
			minWarnings:    1,
			expectedSubstr: "invalid module type",
			description:    "should warn about invalid module type",
		},
		{
			name: "missing control field",
			config: &Config{
				Rules: []Rule{
					{
						Type:       ModuleTypeAuth,
						ModulePath: "pam_unix.so",
					},
				},
			},
			minWarnings:    1,
			expectedSubstr: "missing control field",
			description:    "should warn about missing control field",
		},
		{
			name: "invalid control type",
			config: &Config{
				Rules: []Rule{
					{
						Type:       ModuleTypeAuth,
						Control:    Control{Simple: stringPtr("invalid")},
						ModulePath: "pam_unix.so",
					},
				},
			},
			minWarnings:    1,
			expectedSubstr: "invalid control type",
			description:    "should warn about invalid control type",
		},
		{
			name: "missing service in pam.conf format",
			config: &Config{
				IsPamD: false,
				Rules: []Rule{
					{
						Type:       ModuleTypeAuth,
						Control:    Control{Simple: ptrControlType(ControlRequired)},
						ModulePath: "pam_unix.so",
					},
				},
			},
			minWarnings:    1,
			expectedSubstr: "missing service field",
			description:    "should warn about missing service in pam.conf format",
		},
		{
			name: "service mismatch in pam.d format",
			config: &Config{
				IsPamD:   true,
				FilePath: "/etc/pam.d/sshd",
				Rules: []Rule{
					{
						Service:    "login",
						Type:       ModuleTypeAuth,
						Control:    Control{Simple: ptrControlType(ControlRequired)},
						ModulePath: "pam_unix.so",
					},
				},
			},
			minWarnings:    1,
			expectedSubstr: "service field",
			description:    "should warn about service field mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			editor := NewEditor(tt.config)
			warnings := editor.Validate()

			if len(warnings) < tt.minWarnings {
				t.Errorf("%s: expected at least %d warnings, got %d: %v",
					tt.description, tt.minWarnings, len(warnings), warnings)
				return
			}

			// Check that the expected warning substring is present
			found := false
			for _, warning := range warnings {
				if strings.Contains(warning, tt.expectedSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: expected warning containing '%s', got: %v",
					tt.description, tt.expectedSubstr, warnings)
			}
		})
	}
}

func TestEditor_RemoveRuleEdgeCases(t *testing.T) {
	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, ModulePath: "pam_unix.so"},
		},
	}

	editor := NewEditor(config)

	// Test removing from empty list after removal
	err := editor.RemoveRule(0)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now try to remove from empty list
	err = editor.RemoveRule(0)
	if err == nil {
		t.Error("Expected error when removing from empty list")
	}
}

func TestEditor_UpdateArgumentEdgeCases(t *testing.T) {
	config := &Config{
		Rules: []Rule{
			{
				Type:      ModuleTypeAuth,
				Arguments: []string{"existing=value"},
			},
		},
	}

	editor := NewEditor(config)

	// Test updating argument that doesn't exist - should add it
	err := editor.UpdateArgument(0, "newarg", "newvalue")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify the argument was added
	if len(config.Rules[0].Arguments) != 2 {
		t.Errorf("Expected 2 arguments, got %d", len(config.Rules[0].Arguments))
	}

	found := slices.Contains(config.Rules[0].Arguments, "newarg=newvalue")
	if !found {
		t.Error("New argument not found")
	}
}
