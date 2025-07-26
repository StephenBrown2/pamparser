package pamparser

import (
	"testing"
)

func TestEditor_InsertRuleBefore(t *testing.T) {
	// Create control type variables for tests
	required := ControlRequired
	sufficient := ControlSufficient
	requisite := ControlRequisite

	tests := []struct {
		filter        RuleFilter
		name          string
		initialRules  []Rule
		expectedRules []Rule
		newRule       Rule
		expectError   bool
	}{
		{
			name: "insert before first matching rule",
			initialRules: []Rule{
				{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
				{Type: ModuleTypeAuth, Control: Control{Simple: &sufficient}, ModulePath: "pam_ldap.so"},
				{Type: ModuleTypeAccount, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			},
			newRule:     Rule{Type: ModuleTypeAuth, Control: Control{Simple: &requisite}, ModulePath: "pam_nologin.so"},
			filter:      FilterByModulePath("pam_unix"),
			expectError: false,
			expectedRules: []Rule{
				{Type: ModuleTypeAuth, Control: Control{Simple: &requisite}, ModulePath: "pam_nologin.so"},
				{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
				{Type: ModuleTypeAuth, Control: Control{Simple: &sufficient}, ModulePath: "pam_ldap.so"},
				{Type: ModuleTypeAccount, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			},
		},
		{
			name: "no matching rule for before insertion",
			initialRules: []Rule{
				{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			},
			newRule:     Rule{Type: ModuleTypeAuth, Control: Control{Simple: &requisite}, ModulePath: "pam_nologin.so"},
			filter:      FilterByModulePath("pam_nonexistent"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runInsertionTest(t, tt, func(editor *Editor, rule Rule, filter RuleFilter) error {
				return editor.InsertRuleBefore(rule, filter)
			})
		})
	}
}

// Helper function to reduce duplication in insertion tests
func runInsertionTest(t *testing.T, tt struct {
	filter        RuleFilter
	name          string
	initialRules  []Rule
	expectedRules []Rule
	newRule       Rule
	expectError   bool
}, insertFunc func(*Editor, Rule, RuleFilter) error,
) {
	config := &Config{Rules: tt.initialRules}
	editor := NewEditor(config)

	err := insertFunc(editor, tt.newRule, tt.filter)

	if tt.expectError {
		if err == nil {
			t.Errorf("expected error but got none")
		}
		return
	}

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if len(editor.config.Rules) != len(tt.expectedRules) {
		t.Errorf("expected %d rules, got %d", len(tt.expectedRules), len(editor.config.Rules))
		return
	}

	for i, expected := range tt.expectedRules {
		actual := editor.config.Rules[i]
		if actual.Type != expected.Type || actual.ModulePath != expected.ModulePath {
			t.Errorf("rule %d: expected {Type: %s, ModulePath: %s}, got {Type: %s, ModulePath: %s}",
				i, expected.Type, expected.ModulePath, actual.Type, actual.ModulePath)
		}
	}
}

func TestEditor_InsertRuleAfter(t *testing.T) {
	// Create control type variables for tests
	required := ControlRequired
	sufficient := ControlSufficient
	optional := ControlOptional

	tests := []struct {
		filter        RuleFilter
		name          string
		initialRules  []Rule
		expectedRules []Rule
		newRule       Rule
		expectError   bool
	}{
		{
			name: "insert after last matching rule",
			initialRules: []Rule{
				{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
				{Type: ModuleTypeAuth, Control: Control{Simple: &sufficient}, ModulePath: "pam_ldap.so"},
				{Type: ModuleTypeAccount, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			},
			newRule:     Rule{Type: ModuleTypeAuth, Control: Control{Simple: &optional}, ModulePath: "pam_krb5.so"},
			filter:      FilterByType(ModuleTypeAuth),
			expectError: false,
			expectedRules: []Rule{
				{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
				{Type: ModuleTypeAuth, Control: Control{Simple: &sufficient}, ModulePath: "pam_ldap.so"},
				{Type: ModuleTypeAuth, Control: Control{Simple: &optional}, ModulePath: "pam_krb5.so"},
				{Type: ModuleTypeAccount, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			},
		},
		{
			name: "no matching rule for after insertion",
			initialRules: []Rule{
				{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			},
			newRule:     Rule{Type: ModuleTypeSession, Control: Control{Simple: &optional}, ModulePath: "pam_motd.so"},
			filter:      FilterByType(ModuleTypeSession),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runInsertionTest(t, tt, func(editor *Editor, rule Rule, filter RuleFilter) error {
				return editor.InsertRuleAfter(rule, filter)
			})
		})
	}
}
