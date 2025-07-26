// Package main demonstrates how to work with PAM @include directives using the pamparser library.
package main

import (
	"fmt"
	"log"
	"strings"

	pp "github.com/StephenBrown2/pamparser"
)

func main() {
	fmt.Println("PAM Include Directive Example")
	fmt.Println("============================")

	// Example 1: Parse a typical /etc/pam.d/sudo file with include directives
	sudoConfig := `#%PAM-1.0
session    required     pam_env.so readenv=1 user_readenv=0
session    required     pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive`

	fmt.Println("Example 1: Parsing /etc/pam.d/sudo with @include directives")
	fmt.Println("Input:")
	fmt.Println(sudoConfig)
	fmt.Println()

	parser := pp.NewParser()
	config, err := parser.ParseWithService(strings.NewReader(sudoConfig), true, "sudo")
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	fmt.Printf("Parsed %d rules:\n", len(config.Rules))
	for i, rule := range config.Rules {
		if rule.IsDirective {
			fmt.Printf("  Rule %d: @%s %s", i+1, rule.DirectiveType, rule.DirectiveTarget)
			if rule.Comment != "" {
				fmt.Printf(" # %s", rule.Comment)
			}
			fmt.Println(" [DIRECTIVE]")
		} else {
			fmt.Printf("  Rule %d: %s %s %s %s", i+1, rule.Service, rule.Type,
				formatControl(rule.Control), rule.ModulePath)
			if len(rule.Arguments) > 0 {
				fmt.Printf(" %s", strings.Join(rule.Arguments, " "))
			}
			if rule.Comment != "" {
				fmt.Printf(" # %s", rule.Comment)
			}
			fmt.Println(" [REGULAR]")
		}
	}
	fmt.Println()

	// Example 2: Write the config back out
	fmt.Println("Example 2: Writing config back to string format")
	writer := pp.NewWriter()
	output, err := writer.WriteString(config)
	if err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}

	fmt.Println("Output:")
	fmt.Println(output)
	fmt.Println()

	// Example 3: Add a new include directive
	fmt.Println("Example 3: Adding a new @include directive")

	editor := pp.NewEditor(config)

	// Create a new include directive for common-password
	newIncludeRule := pp.Rule{
		IsDirective:     true,
		DirectiveType:   "include",
		DirectiveTarget: "common-password",
		Comment:         "Password management",
		LineNumber:      len(config.Rules) + 1,
	}

	fmt.Printf("Creating new directive: @%s %s # %s\n",
		newIncludeRule.DirectiveType, newIncludeRule.DirectiveTarget, newIncludeRule.Comment)

	editor.AddRule(newIncludeRule)

	// Debug: check what's in the config after adding
	updatedConfig := editor.GetConfig()
	fmt.Printf("After adding, config has %d rules:\n", len(updatedConfig.Rules))
	for i, rule := range updatedConfig.Rules {
		if rule.IsDirective {
			fmt.Printf("  Rule %d: @%s %s (comment: '%s')\n",
				i+1, rule.DirectiveType, rule.DirectiveTarget, rule.Comment)
		} else {
			fmt.Printf("  Rule %d: %s %s (regular)\n", i+1, rule.Type, rule.ModulePath)
		}
	}

	updatedOutput, err := writer.WriteString(editor.GetConfig())
	if err != nil {
		log.Fatalf("Failed to write updated config: %v", err)
	}

	fmt.Println("Updated config with new @include directive:")
	fmt.Println(updatedOutput)
	fmt.Println()

	// Example 4: Find and count include directives
	fmt.Println("Example 4: Finding include directives")
	includeIndices := editor.FindRules(func(rule pp.Rule) bool {
		return rule.IsDirective && rule.DirectiveType == "include"
	})

	fmt.Printf("Found %d include directives:\n", len(includeIndices))
	config = editor.GetConfig()
	for _, index := range includeIndices {
		rule := config.Rules[index]
		fmt.Printf("  - @include %s", rule.DirectiveTarget)
		if rule.Comment != "" {
			fmt.Printf(" # %s", rule.Comment)
		}
		fmt.Println()
	}
	fmt.Println()

	// Example 5: Validation with include directives
	fmt.Println("Example 5: Validation with include directives")
	issues := editor.Validate()

	fmt.Printf("Validation results: %d issues\n", len(issues))
	if len(issues) > 0 {
		fmt.Println("Issues:")
		for _, issue := range issues {
			fmt.Printf("  - %s\n", issue)
		}
	} else {
		fmt.Println("No validation issues found!")
	}
}

func formatControl(control pp.Control) string {
	if control.Simple != nil {
		prefix := ""
		if control.Optional {
			prefix = "-"
		}
		return prefix + string(*control.Simple)
	}
	if control.Complex != nil {
		return "[complex]" // Simplified for display
	}
	return "[unknown]"
}
