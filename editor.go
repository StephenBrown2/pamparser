package pamparser

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Editor provides functionality to modify PAM configurations
type Editor struct {
	config *Config
}

// NewEditor creates a new editor for a PAM configuration
func NewEditor(config *Config) *Editor {
	return &Editor{config: config}
}

// RuleFilter is a function type for filtering rules
type RuleFilter func(rule Rule) bool

// FilterByService creates a filter for rules with a specific service
func FilterByService(service string) RuleFilter {
	return func(rule Rule) bool {
		return strings.EqualFold(rule.Service, service)
	}
}

// FilterByType creates a filter for rules with a specific module type
func FilterByType(moduleType ModuleType) RuleFilter {
	return func(rule Rule) bool {
		return rule.Type == moduleType
	}
}

// FilterByModulePath creates a filter for rules with a specific module path
func FilterByModulePath(modulePath string) RuleFilter {
	return func(rule Rule) bool {
		return strings.Contains(rule.ModulePath, modulePath)
	}
}

// FilterByControl creates a filter for rules with a specific simple control type
func FilterByControl(control ControlType) RuleFilter {
	return func(rule Rule) bool {
		return rule.Control.Simple != nil && *rule.Control.Simple == control
	}
}

// CombineFilters combines multiple filters with AND logic
func CombineFilters(filters ...RuleFilter) RuleFilter {
	return func(rule Rule) bool {
		for _, filter := range filters {
			if !filter(rule) {
				return false
			}
		}
		return true
	}
}

// FindRules finds all rules matching the given filter
func (e *Editor) FindRules(filter RuleFilter) []int {
	var indices []int
	for i, rule := range e.config.Rules {
		if filter(rule) {
			indices = append(indices, i)
		}
	}
	return indices
}

// GetRule returns a copy of the rule at the specified index
func (e *Editor) GetRule(index int) (*Rule, error) {
	if index < 0 || index >= len(e.config.Rules) {
		return nil, fmt.Errorf("rule index %d out of range [0, %d)", index, len(e.config.Rules))
	}

	rule := e.config.Rules[index]
	// Return a copy to prevent accidental modifications
	return &Rule{
		Service:      rule.Service,
		Type:         rule.Type,
		Control:      rule.Control,
		ModulePath:   rule.ModulePath,
		Arguments:    append([]string(nil), rule.Arguments...),
		Comment:      rule.Comment,
		LineNumber:   rule.LineNumber,
		Continuation: rule.Continuation,
	}, nil
}

// AddRule adds a new rule to the configuration in the correct position based on module type
func (e *Editor) AddRule(rule Rule) {
	// For directives, add at the end to preserve their order
	if rule.IsDirective {
		e.config.Rules = append(e.config.Rules, rule)
		return
	}

	// Find the correct position to insert the rule based on module type ordering
	insertPos := e.findInsertPosition(rule.Type)

	// Insert the rule at the correct position
	e.config.Rules = append(e.config.Rules, Rule{})
	copy(e.config.Rules[insertPos+1:], e.config.Rules[insertPos:])
	e.config.Rules[insertPos] = rule
}

// findInsertPosition finds the correct position to insert a rule of the given type
func (e *Editor) findInsertPosition(moduleType ModuleType) int {
	targetOrder := GetModuleTypeOrder(moduleType)

	// Find the last rule of the same type or the position where it should be inserted
	for i := len(e.config.Rules) - 1; i >= 0; i-- {
		ruleOrder := GetModuleTypeOrder(e.config.Rules[i].Type)
		if ruleOrder <= targetOrder {
			return i + 1
		}
	}

	return 0 // Insert at the beginning if no suitable position found
}

// InsertRule inserts a rule at the specified position
func (e *Editor) InsertRule(index int, rule Rule) error {
	if index < 0 || index > len(e.config.Rules) {
		return fmt.Errorf("insert index %d out of range [0, %d]", index, len(e.config.Rules))
	}

	// Expand slice and insert
	e.config.Rules = append(e.config.Rules, Rule{})
	copy(e.config.Rules[index+1:], e.config.Rules[index:])
	e.config.Rules[index] = rule

	return nil
}

// InsertRuleBefore inserts a rule before the first rule matching the filter
func (e *Editor) InsertRuleBefore(rule Rule, filter RuleFilter) error {
	for i, existingRule := range e.config.Rules {
		if filter(existingRule) {
			return e.InsertRule(i, rule)
		}
	}
	return fmt.Errorf("no rule found matching the pattern for before insertion")
}

// InsertRuleAfter inserts a rule after the last rule matching the filter
func (e *Editor) InsertRuleAfter(rule Rule, filter RuleFilter) error {
	lastMatchIndex := -1

	// Find the last matching rule
	for i, existingRule := range e.config.Rules {
		if filter(existingRule) {
			lastMatchIndex = i
		}
	}

	if lastMatchIndex == -1 {
		return fmt.Errorf("no rule found matching the pattern for after insertion")
	}

	return e.InsertRule(lastMatchIndex+1, rule)
}

// UpdateRule updates the rule at the specified index
func (e *Editor) UpdateRule(index int, rule Rule) error {
	if index < 0 || index >= len(e.config.Rules) {
		return fmt.Errorf("rule index %d out of range [0, %d)", index, len(e.config.Rules))
	}

	e.config.Rules[index] = rule
	return nil
}

// RemoveRule removes the rule at the specified index
func (e *Editor) RemoveRule(index int) error {
	if index < 0 || index >= len(e.config.Rules) {
		return fmt.Errorf("rule index %d out of range [0, %d)", index, len(e.config.Rules))
	}

	e.config.Rules = append(e.config.Rules[:index], e.config.Rules[index+1:]...)
	return nil
}

// RemoveRules removes all rules matching the given filter
func (e *Editor) RemoveRules(filter RuleFilter) int {
	var newRules []Rule
	removed := 0

	for _, rule := range e.config.Rules {
		if filter(rule) {
			removed++
		} else {
			newRules = append(newRules, rule)
		}
	}

	e.config.Rules = newRules
	return removed
}

// UpdateArgument updates or adds a module argument
func (e *Editor) UpdateArgument(ruleIndex int, argName, argValue string) error {
	if ruleIndex < 0 || ruleIndex >= len(e.config.Rules) {
		return fmt.Errorf("rule index %d out of range [0, %d)", ruleIndex, len(e.config.Rules))
	}

	rule := &e.config.Rules[ruleIndex]

	// Look for existing argument
	for i, arg := range rule.Arguments {
		if strings.HasPrefix(arg, argName+"=") {
			rule.Arguments[i] = argName + "=" + argValue
			return nil
		}
		if arg == argName {
			rule.Arguments[i] = argName + "=" + argValue
			return nil
		}
	}

	// Add new argument
	rule.Arguments = append(rule.Arguments, argName+"="+argValue)
	return nil
}

// RemoveArgument removes a module argument
func (e *Editor) RemoveArgument(ruleIndex int, argName string) error {
	if ruleIndex < 0 || ruleIndex >= len(e.config.Rules) {
		return fmt.Errorf("rule index %d out of range [0, %d)", ruleIndex, len(e.config.Rules))
	}

	rule := &e.config.Rules[ruleIndex]
	var newArgs []string

	for _, arg := range rule.Arguments {
		if !strings.HasPrefix(arg, argName+"=") && arg != argName {
			newArgs = append(newArgs, arg)
		}
	}

	rule.Arguments = newArgs
	return nil
}

// SetControl sets the control field for a rule
func (e *Editor) SetControl(ruleIndex int, control Control) error {
	if ruleIndex < 0 || ruleIndex >= len(e.config.Rules) {
		return fmt.Errorf("rule index %d out of range [0, %d)", ruleIndex, len(e.config.Rules))
	}

	e.config.Rules[ruleIndex].Control = control
	return nil
}

// MoveRule moves a rule from one position to another
func (e *Editor) MoveRule(fromIndex, toIndex int) error {
	if fromIndex < 0 || fromIndex >= len(e.config.Rules) {
		return fmt.Errorf("from index %d out of range [0, %d)", fromIndex, len(e.config.Rules))
	}
	if toIndex < 0 || toIndex >= len(e.config.Rules) {
		return fmt.Errorf("to index %d out of range [0, %d)", toIndex, len(e.config.Rules))
	}

	if fromIndex == toIndex {
		return nil
	}

	rule := e.config.Rules[fromIndex]

	// Remove from original position
	e.config.Rules = append(e.config.Rules[:fromIndex], e.config.Rules[fromIndex+1:]...)

	// Adjust toIndex if necessary
	if toIndex > fromIndex {
		toIndex--
	}

	// Insert at new position
	e.config.Rules = append(e.config.Rules, Rule{})
	copy(e.config.Rules[toIndex+1:], e.config.Rules[toIndex:])
	e.config.Rules[toIndex] = rule

	return nil
}

// AddComment adds a standalone comment to the configuration
func (e *Editor) AddComment(comment string) {
	e.config.Comments = append(e.config.Comments, comment)
}

// GetConfig returns a copy of the current configuration
func (e *Editor) GetConfig() *Config {
	// Create a deep copy
	newConfig := &Config{
		Rules:    make([]Rule, len(e.config.Rules)),
		Comments: append([]string(nil), e.config.Comments...),
		FilePath: e.config.FilePath,
		IsPamD:   e.config.IsPamD,
	}

	for i, rule := range e.config.Rules {
		newConfig.Rules[i] = Rule{
			Service:      rule.Service,
			Type:         rule.Type,
			Control:      rule.Control,
			ModulePath:   rule.ModulePath,
			Arguments:    append([]string(nil), rule.Arguments...),
			Comment:      rule.Comment,
			LineNumber:   rule.LineNumber,
			Continuation: rule.Continuation,

			// Directive fields
			IsDirective:     rule.IsDirective,
			DirectiveType:   rule.DirectiveType,
			DirectiveTarget: rule.DirectiveTarget,
		}

		// Deep copy complex control if present
		if rule.Control.Complex != nil {
			newConfig.Rules[i].Control.Complex = make(map[ReturnValue]any)
			for k, v := range rule.Control.Complex {
				newConfig.Rules[i].Control.Complex[k] = v
			}
		}
	}

	return newConfig
}

// Validate checks the configuration for common issues
func (e *Editor) Validate() []string {
	var warnings []string

	for i, rule := range e.config.Rules {
		// Skip validation for directives - they have different structure
		if rule.IsDirective {
			// Only validate directive-specific fields
			if rule.DirectiveType == "" {
				warnings = append(warnings, fmt.Sprintf("Rule %d: directive missing type", i))
			}
			if rule.DirectiveType == "include" && rule.DirectiveTarget == "" {
				warnings = append(warnings, fmt.Sprintf("Rule %d: @include directive missing target", i))
			}
			continue
		}

		// Check for missing required fields in regular rules
		if rule.Type == "" {
			warnings = append(warnings, fmt.Sprintf("Rule %d: missing module type", i))
		}
		if rule.ModulePath == "" {
			warnings = append(warnings, fmt.Sprintf("Rule %d: missing module path", i))
		}

		// Check for valid module type
		if !IsValidModuleType(string(rule.Type)) {
			warnings = append(warnings, fmt.Sprintf("Rule %d: invalid module type '%s'", i, rule.Type))
		}

		// Check control field
		if rule.Control.Simple == nil && rule.Control.Complex == nil {
			warnings = append(warnings, fmt.Sprintf("Rule %d: missing control field", i))
		}

		if rule.Control.Simple != nil && !IsValidControlType(string(*rule.Control.Simple)) {
			warnings = append(warnings, fmt.Sprintf("Rule %d: invalid control type '%s'", i, *rule.Control.Simple))
		}

		// Check for service field inconsistencies
		if e.config.IsPamD {
			// For pam.d format, service field can be present (auto-extracted from filename)
			// but if present, it should be consistent
			expectedService := ""
			if e.config.FilePath != "" && strings.Contains(e.config.FilePath, "/pam.d/") {
				expectedService = filepath.Base(e.config.FilePath)
			}
			if rule.Service != "" && expectedService != "" && rule.Service != expectedService {
				warnings = append(warnings, fmt.Sprintf("Rule %d: service field '%s' doesn't match expected service '%s' for pam.d format", i, rule.Service, expectedService))
			}
		} else if rule.Service == "" {
			// Check for missing service field in pam.conf format
			warnings = append(warnings, fmt.Sprintf("Rule %d: missing service field in pam.conf format", i))
		}
	}

	return warnings
}

// SortRulesByType sorts rules by module type while preserving relative order within each type
func (e *Editor) SortRulesByType() {
	// Group rules by normalized type while preserving original order within each type
	typeGroups := make(map[ModuleType][]Rule)
	typeOrder := []ModuleType{ModuleTypeAccount, ModuleTypeAuth, ModuleTypePassword, ModuleTypeSession, ModuleTypeSessionNoninteractive}

	// Group existing rules by normalized type (negative and positive types grouped together)
	for _, rule := range e.config.Rules {
		normalizedType := GetNormalizedModuleType(rule.Type)
		typeGroups[normalizedType] = append(typeGroups[normalizedType], rule)
	}

	// Rebuild rules array in correct order
	var sortedRules []Rule

	// Add rules in the standard order
	for _, moduleType := range typeOrder {
		if rules, exists := typeGroups[moduleType]; exists {
			sortedRules = append(sortedRules, rules...)
		}
	}

	// Add any rules with unknown types at the end
	for moduleType, rules := range typeGroups {
		found := false
		for _, knownType := range typeOrder {
			if moduleType == knownType {
				found = true
				break
			}
		}
		if !found {
			sortedRules = append(sortedRules, rules...)
		}
	}

	e.config.Rules = sortedRules
}
