package pamparser

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Writer handles writing PAM configurations to files
type Writer struct {
	// Configuration options
	IndentSize    int
	MaxLineLength int
}

// NewWriter creates a new PAM configuration writer
func NewWriter() *Writer {
	return &Writer{
		IndentSize:    0,
		MaxLineLength: 80,
	}
}

// formatControl formats a Control structure back to string representation
func (w *Writer) formatControl(control Control) string {
	var result strings.Builder

	if control.Optional {
		result.WriteString("-")
	}

	if control.Simple != nil {
		result.WriteString(string(*control.Simple))
		return result.String()
	}

	if control.Complex != nil {
		result.WriteString("[")

		// Sort keys for consistent output
		var keys []string
		for k := range control.Complex {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)

		var pairs []string
		for _, key := range keys {
			value := control.Complex[ReturnValue(key)]
			var valueStr string

			switch v := value.(type) {
			case ActionType:
				valueStr = string(v)
			case int:
				valueStr = strconv.Itoa(v)
			default:
				valueStr = fmt.Sprintf("%v", v)
			}

			pairs = append(pairs, fmt.Sprintf("%s=%s", key, valueStr))
		}

		result.WriteString(strings.Join(pairs, " "))
		result.WriteString("]")
	}

	return result.String()
}

// formatArguments formats module arguments, handling square bracket escaping
func (w *Writer) formatArguments(args []string) string {
	if len(args) == 0 {
		return ""
	}

	var formatted []string
	for _, arg := range args {
		// Check if argument contains spaces or special characters
		if strings.ContainsAny(arg, " \t\n[]") {
			// Escape ] characters and wrap in brackets
			escaped := strings.ReplaceAll(arg, "]", `\]`)
			formatted = append(formatted, fmt.Sprintf("[%s]", escaped))
		} else {
			formatted = append(formatted, arg)
		}
	}

	return strings.Join(formatted, " ")
}

// formatRule formats a single Rule back to string representation
func (w *Writer) formatRule(rule Rule) string {
	var parts []string

	// Handle directives (e.g., @include)
	if rule.IsDirective {
		parts = append(parts, "@"+rule.DirectiveType)
		if rule.DirectiveTarget != "" {
			parts = append(parts, rule.DirectiveTarget)
		}

		// Add arguments if present
		if len(rule.Arguments) > 0 {
			args := w.formatArguments(rule.Arguments)
			parts = append(parts, args)
		}

		line := strings.Join(parts, " ")

		// Add inline comment if present
		if rule.Comment != "" {
			line += " # " + rule.Comment
		}

		return line
	}

	// Handle regular PAM rules
	// Add service if present (for /etc/pam.conf format)
	if rule.Service != "" {
		parts = append(parts, rule.Service)
	}

	// Add type
	parts = append(parts, string(rule.Type))

	// Add control
	parts = append(parts, w.formatControl(rule.Control))

	// Add module path
	parts = append(parts, rule.ModulePath)

	// Add arguments
	if len(rule.Arguments) > 0 {
		args := w.formatArguments(rule.Arguments)
		parts = append(parts, args)
	}

	line := strings.Join(parts, " ")

	// Add inline comment if present
	if rule.Comment != "" {
		line += " # " + rule.Comment
	}

	return line
}

// handleLineContinuation splits a long line into multiple lines with continuation
func (w *Writer) handleLineContinuation(line string) []string {
	if w.MaxLineLength <= 0 || len(line) <= w.MaxLineLength {
		return []string{line}
	}

	var lines []string
	remaining := line

	for len(remaining) > w.MaxLineLength {
		// Find a good break point (prefer breaking at spaces)
		breakPoint := w.MaxLineLength
		for i := w.MaxLineLength - 1; i > w.MaxLineLength/2; i-- {
			if remaining[i] == ' ' {
				breakPoint = i
				break
			}
		}

		// Add continuation marker and create line
		currentLine := strings.TrimSpace(remaining[:breakPoint]) + " \\"
		lines = append(lines, currentLine)

		// Continue with remaining text
		remaining = strings.TrimSpace(remaining[breakPoint:])
	}

	// Add the final part
	if remaining != "" {
		lines = append(lines, remaining)
	}

	return lines
}

// Write writes a PAM configuration to the provided writer
func (w *Writer) Write(config *Config, writer io.Writer) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Create a copy of config to avoid modifying the original
	configCopy := *config
	configCopy.Rules = make([]Rule, len(config.Rules))
	copy(configCopy.Rules, config.Rules)

	// Sort rules by type to ensure proper grouping
	w.sortRulesByType(&configCopy)

	// Pre-allocate lines slice with estimated capacity
	lines := make([]string, 0, len(config.Rules)+len(config.Comments)+5)

	// Write standalone comments first
	for _, comment := range configCopy.Comments {
		lines = append(lines, "# "+comment)
	}

	// Group rules by type and add section comments
	currentNormalizedType := ModuleType("")
	for _, rule := range configCopy.Rules {
		// Add section comment for new module type (skip for directives)
		if !rule.IsDirective {
			normalizedType := GetNormalizedModuleType(rule.Type)
			if normalizedType != currentNormalizedType {
				if len(lines) > 0 && !strings.HasPrefix(lines[len(lines)-1], "#") {
					lines = append(lines, "") // Add blank line before new section
				}
				currentNormalizedType = normalizedType
			}
		}

		ruleLine := w.formatRule(rule)

		// Handle line continuation if needed
		ruleLines := w.handleLineContinuation(ruleLine)
		lines = append(lines, ruleLines...)
	}

	// Write all lines
	for i, line := range lines {
		if _, err := writer.Write([]byte(line)); err != nil {
			return fmt.Errorf("error writing line %d: %w", i+1, err)
		}
		if _, err := writer.Write([]byte("\n")); err != nil {
			return fmt.Errorf("error writing newline for line %d: %w", i+1, err)
		}
	}

	return nil
}

// sortRulesByType sorts rules by module type while preserving relative order within each type
func (w *Writer) sortRulesByType(config *Config) {
	// Separate directives from regular rules
	var directives []Rule
	var regularRules []Rule

	for _, rule := range config.Rules {
		if rule.IsDirective {
			directives = append(directives, rule)
		} else {
			regularRules = append(regularRules, rule)
		}
	}

	// Group regular rules by normalized type while preserving original order within each type
	typeGroups := make(map[ModuleType][]Rule)
	typeOrder := []ModuleType{ModuleTypeAccount, ModuleTypeAuth, ModuleTypePassword, ModuleTypeSession}

	// Group existing rules by normalized type (negative and positive types grouped together)
	for _, rule := range regularRules {
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

	// Add any rules with unknown types
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

	// Add directives at the end to preserve their inclusion order
	sortedRules = append(sortedRules, directives...)

	config.Rules = sortedRules
}

// WriteString returns the PAM configuration as a string
func (w *Writer) WriteString(config *Config) (string, error) {
	var builder strings.Builder
	err := w.Write(config, &builder)
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}
