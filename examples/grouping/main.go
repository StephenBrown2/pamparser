// Package main demonstrates automatic rule grouping by module type functionality
// of the PAM parser library, showing how rules are organized and sorted.
package main

import (
	"fmt"
	"log"
	"strings"

	pp "github.com/StephenBrown2/pamparser"
)

func main() {
	fmt.Println("=== PAM Configuration Rule Grouping Demo ===")
	fmt.Println()

	// Sample unsorted configuration
	unsortedConfig := `# Mixed PAM configuration
session    required     pam_unix.so
auth       required     pam_unix.so     nullok
password   required     pam_unix.so     obscure
account    required     pam_unix.so
auth       sufficient   pam_ldap.so
session    optional     pam_motd.so
account    sufficient   pam_ldap.so
`

	fmt.Println("Original (unsorted) configuration:")
	fmt.Println(unsortedConfig)

	// Parse the configuration
	parser := pp.NewParser()
	config, err := parser.Parse(strings.NewReader(unsortedConfig), true) // true = pam.d format
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Parsed rules before sorting:")
	for i, rule := range config.Rules {
		fmt.Printf("%d. Type: %s, Control: %s, Module: %s\n",
			i+1, rule.Type, formatControl(rule.Control), rule.ModulePath)
	}

	// Create editor and sort rules
	editor := pp.NewEditor(config)
	editor.SortRulesByType()

	fmt.Println("\nAfter automatic grouping by module type:")

	// Write back to string
	writer := pp.NewWriter()
	output, err := writer.WriteString(config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(output)

	// Demonstrate adding a new rule
	fmt.Println("Adding a new 'auth' rule to see insertion behavior:")
	optional := pp.ControlOptional
	newAuthRule := pp.Rule{
		Type:       pp.ModuleTypeAuth,
		Control:    pp.Control{Simple: &optional},
		ModulePath: "pam_krb5.so",
		Arguments:  []string{"try_first_pass"},
	}

	editor.AddRule(newAuthRule)

	// Write final configuration
	finalOutput, err := writer.WriteString(config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Final configuration with new auth rule properly positioned:")
	fmt.Println(finalOutput)

	fmt.Println("Note: Rules are automatically grouped in order: account, auth, password, session")
}

// Helper function to format control for display
func formatControl(control pp.Control) string {
	if control.Simple != nil {
		return string(*control.Simple)
	}
	return "[complex]"
}
