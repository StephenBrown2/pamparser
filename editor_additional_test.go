package pamparser

import (
	"testing"
)

func TestEditor_GetRule(t *testing.T) {
	required := ControlRequired
	sufficient := ControlSufficient

	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so", Arguments: []string{"nullok"}},
			{Type: ModuleTypeAccount, Control: Control{Simple: &sufficient}, ModulePath: "pam_ldap.so"},
		},
	}

	editor := NewEditor(config)

	// Test valid index
	rule, err := editor.GetRule(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rule.Type != ModuleTypeAuth || rule.ModulePath != "pam_unix.so" {
		t.Errorf("expected auth pam_unix.so, got %s %s", rule.Type, rule.ModulePath)
	}

	// Test that we get a copy (modifying returned rule shouldn't affect original)
	rule.Arguments[0] = "modified"
	if config.Rules[0].Arguments[0] == "modified" {
		t.Error("GetRule should return a copy, not a reference")
	}

	// Test invalid indices
	_, err = editor.GetRule(-1)
	if err == nil {
		t.Error("expected error for negative index")
	}

	_, err = editor.GetRule(10)
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestEditor_UpdateRule(t *testing.T) {
	required := ControlRequired
	optional := ControlOptional

	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
		},
	}

	editor := NewEditor(config)

	// Test valid update
	newRule := Rule{Type: ModuleTypeAuth, Control: Control{Simple: &optional}, ModulePath: "pam_ldap.so"}
	err := editor.UpdateRule(0, newRule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.Rules[0].ModulePath != "pam_ldap.so" || *config.Rules[0].Control.Simple != ControlOptional {
		t.Error("rule was not updated correctly")
	}

	// Test invalid indices
	err = editor.UpdateRule(-1, newRule)
	if err == nil {
		t.Error("expected error for negative index")
	}

	err = editor.UpdateRule(10, newRule)
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestEditor_RemoveArgument(t *testing.T) {
	required := ControlRequired

	config := &Config{
		Rules: []Rule{
			{
				Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so",
				Arguments: []string{"nullok", "try_first_pass", "use_authtok"},
			},
		},
	}

	editor := NewEditor(config)

	// Test removing existing argument
	err := editor.RemoveArgument(0, "try_first_pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"nullok", "use_authtok"}
	if len(config.Rules[0].Arguments) != 2 {
		t.Errorf("expected 2 arguments, got %d", len(config.Rules[0].Arguments))
	}

	for i, arg := range config.Rules[0].Arguments {
		if arg != expected[i] {
			t.Errorf("expected argument %d to be %s, got %s", i, expected[i], arg)
		}
	}

	// Test removing argument with equals (key=value format)
	config.Rules[0].Arguments = []string{"debug=true", "nullok"}
	err = editor.RemoveArgument(0, "debug")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(config.Rules[0].Arguments) != 1 || config.Rules[0].Arguments[0] != "nullok" {
		t.Error("failed to remove key=value argument")
	}

	// Test invalid index
	err = editor.RemoveArgument(-1, "test")
	if err == nil {
		t.Error("expected error for negative index")
	}

	err = editor.RemoveArgument(10, "test")
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestEditor_SetControl(t *testing.T) {
	required := ControlRequired
	optional := ControlOptional

	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
		},
	}

	editor := NewEditor(config)

	// Test setting control
	newControl := Control{Simple: &optional, Optional: true}
	err := editor.SetControl(0, newControl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if *config.Rules[0].Control.Simple != ControlOptional || !config.Rules[0].Control.Optional {
		t.Error("control was not set correctly")
	}

	// Test invalid indices
	err = editor.SetControl(-1, newControl)
	if err == nil {
		t.Error("expected error for negative index")
	}

	err = editor.SetControl(10, newControl)
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestEditor_MoveRule(t *testing.T) {
	required := ControlRequired
	sufficient := ControlSufficient
	optional := ControlOptional

	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			{Type: ModuleTypeAuth, Control: Control{Simple: &sufficient}, ModulePath: "pam_ldap.so"},
			{Type: ModuleTypeAuth, Control: Control{Simple: &optional}, ModulePath: "pam_krb5.so"},
		},
	}

	editor := NewEditor(config)

	// Test moving rule from position 0 to position 2
	err := editor.MoveRule(0, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After moving from 0 to 2, the order should be: ldap, unix, krb5
	// (first rule moved to position after removal adjustment)
	expectedOrder := []string{"pam_ldap.so", "pam_unix.so", "pam_krb5.so"}
	for i, expected := range expectedOrder {
		if config.Rules[i].ModulePath != expected {
			t.Errorf("expected rule %d to be %s, got %s", i, expected, config.Rules[i].ModulePath)
		}
	}

	// Test moving to same position (should be no-op)
	err = editor.MoveRule(1, 1)
	if err != nil {
		t.Fatalf("unexpected error for same position move: %v", err)
	}

	// Test invalid indices
	err = editor.MoveRule(-1, 1)
	if err == nil {
		t.Error("expected error for negative from index")
	}

	err = editor.MoveRule(1, -1)
	if err == nil {
		t.Error("expected error for negative to index")
	}

	err = editor.MoveRule(10, 1)
	if err == nil {
		t.Error("expected error for out-of-range from index")
	}

	err = editor.MoveRule(1, 10)
	if err == nil {
		t.Error("expected error for out-of-range to index")
	}
}

func TestEditor_AddComment(t *testing.T) {
	config := &Config{Comments: []string{"existing comment"}}
	editor := NewEditor(config)

	editor.AddComment("new comment")

	if len(config.Comments) != 2 {
		t.Errorf("expected 2 comments, got %d", len(config.Comments))
	}

	if config.Comments[1] != "new comment" {
		t.Errorf("expected 'new comment', got '%s'", config.Comments[1])
	}
}

func TestEditor_GetConfig(t *testing.T) {
	required := ControlRequired

	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so", Arguments: []string{"nullok"}},
		},
		Comments: []string{"test comment"},
		FilePath: "/etc/pam.d/test",
		IsPamD:   true,
	}

	// Add complex control to test deep copy
	config.Rules[0].Control.Complex = map[ReturnValue]any{
		ReturnSuccess: ActionOK,
		ReturnDefault: ActionBad,
	}

	editor := NewEditor(config)
	configCopy := editor.GetConfig()

	// Verify it's a deep copy
	if configCopy == config {
		t.Error("GetConfig should return a copy, not the same instance")
	}

	// Verify content is copied correctly
	if configCopy.FilePath != config.FilePath || configCopy.IsPamD != config.IsPamD {
		t.Error("config metadata not copied correctly")
	}

	if len(configCopy.Rules) != len(config.Rules) || len(configCopy.Comments) != len(config.Comments) {
		t.Error("rules or comments not copied correctly")
	}

	// Test modifying copy doesn't affect original
	configCopy.Rules[0].Arguments[0] = "modified"
	if config.Rules[0].Arguments[0] == "modified" {
		t.Error("modifying copy affected original")
	}

	// Test complex control deep copy
	configCopy.Rules[0].Control.Complex[ReturnSuccess] = ActionDie
	if config.Rules[0].Control.Complex[ReturnSuccess] != ActionOK {
		t.Error("modifying copy's complex control affected original")
	}
}

func TestEditor_RemoveRules(t *testing.T) {
	required := ControlRequired
	sufficient := ControlSufficient

	config := &Config{
		Rules: []Rule{
			{Type: ModuleTypeAuth, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
			{Type: ModuleTypeAuth, Control: Control{Simple: &sufficient}, ModulePath: "pam_ldap.so"},
			{Type: ModuleTypeAccount, Control: Control{Simple: &required}, ModulePath: "pam_unix.so"},
		},
	}

	editor := NewEditor(config)

	// Remove all rules containing "pam_unix"
	removed := editor.RemoveRules(FilterByModulePath("pam_unix"))

	if removed != 2 {
		t.Errorf("expected to remove 2 rules, got %d", removed)
	}

	if len(config.Rules) != 1 {
		t.Errorf("expected 1 remaining rule, got %d", len(config.Rules))
	}

	if config.Rules[0].ModulePath != "pam_ldap.so" {
		t.Errorf("expected remaining rule to be pam_ldap.so, got %s", config.Rules[0].ModulePath)
	}
}

func TestFilterByControl(t *testing.T) {
	required := ControlRequired
	sufficient := ControlSufficient

	rules := []Rule{
		{Control: Control{Simple: &required}},
		{Control: Control{Simple: &sufficient}},
		{Control: Control{Complex: map[ReturnValue]any{ReturnSuccess: ActionOK}}},
	}

	filter := FilterByControl(ControlRequired)

	if !filter(rules[0]) {
		t.Error("filter should match required control")
	}

	if filter(rules[1]) {
		t.Error("filter should not match sufficient control")
	}

	if filter(rules[2]) {
		t.Error("filter should not match complex control")
	}
}
