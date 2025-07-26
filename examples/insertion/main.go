// Package main demonstrates pattern-based rule insertion functionality of the PAM
// parser library, showing how to insert rules before/after specific patterns.
package main

import (
	"fmt"
	"log"
	"strings"

	pp "github.com/StephenBrown2/pamparser"
)

func main() {
	fmt.Println("=== PAM Rule Insertion Demonstration ===")
	fmt.Println()

	// Sample configuration
	configStr := `# Sample PAM configuration
auth       required     pam_unix.so     nullok
auth       sufficient   pam_ldap.so
account    required     pam_unix.so
password   required     pam_unix.so     obscure
session    required     pam_unix.so
session    optional     pam_motd.so
`

	fmt.Println("Original configuration:")
	fmt.Println(configStr)

	// Parse the configuration
	parser := pp.NewParser()
	config, err := parser.Parse(strings.NewReader(configStr), true)
	if err != nil {
		log.Fatal(err)
	}

	editor := pp.NewEditor(config)
	writer := pp.NewWriter()

	// Demonstration 1: Insert before first pam_unix rule
	fmt.Println("=== Demonstration 1: Insert before first pam_unix rule ===")

	requisite := pp.ControlRequisite
	newRule1 := pp.Rule{
		Type:       pp.ModuleTypeAuth,
		Control:    pp.Control{Simple: &requisite},
		ModulePath: "pam_nologin.so",
	}

	err = editor.InsertRuleBefore(newRule1, pp.FilterByModulePath("pam_unix"))
	if err != nil {
		log.Printf("Error: %v", err)
	} else {
		fmt.Println("✓ Successfully inserted requisite pam_nologin.so before first pam_unix rule")
	}

	output, _ := writer.WriteString(config)
	fmt.Println(output)

	// Demonstration 2: Insert after all auth rules
	fmt.Println("=== Demonstration 2: Insert after all auth rules ===")

	optional := pp.ControlOptional
	newRule2 := pp.Rule{
		Type:       pp.ModuleTypeAuth,
		Control:    pp.Control{Simple: &optional},
		ModulePath: "pam_krb5.so",
		Arguments:  []string{"try_first_pass"},
	}

	err = editor.InsertRuleAfter(newRule2, pp.FilterByType(pp.ModuleTypeAuth))
	if err != nil {
		log.Printf("Error: %v", err)
	} else {
		fmt.Println("✓ Successfully inserted optional pam_krb5.so after last auth rule")
	}

	output, _ = writer.WriteString(config)
	fmt.Println(output)

	// Demonstration 3: Insert before specific module within a type
	fmt.Println("=== Demonstration 3: Insert before pam_motd in session rules ===")

	sufficient := pp.ControlSufficient
	newRule3 := pp.Rule{
		Type:       pp.ModuleTypeSession,
		Control:    pp.Control{Simple: &sufficient},
		ModulePath: "pam_systemd.so",
	}

	err = editor.InsertRuleBefore(newRule3, pp.FilterByModulePath("pam_motd"))
	if err != nil {
		log.Printf("Error: %v", err)
	} else {
		fmt.Println("✓ Successfully inserted sufficient pam_systemd.so before pam_motd rule")
	}

	output, _ = writer.WriteString(config)
	fmt.Println(output)

	// Demonstration 4: Error handling - no matching pattern
	fmt.Println("=== Demonstration 4: Error handling ===")

	required := pp.ControlRequired
	newRule4 := pp.Rule{
		Type:       pp.ModuleTypePassword,
		Control:    pp.Control{Simple: &required},
		ModulePath: "pam_cracklib.so",
	}

	err = editor.InsertRuleBefore(newRule4, pp.FilterByModulePath("pam_nonexistent"))
	if err != nil {
		fmt.Printf("✗ Expected error: %v\n", err)
	}

	fmt.Println()
	fmt.Println("=== Summary ===")
	fmt.Println("The PAM library now supports:")
	fmt.Println("• InsertRuleBefore() - Insert before first matching rule")
	fmt.Println("• InsertRuleAfter() - Insert after last matching rule")
	fmt.Println("• Flexible pattern matching using RuleFilter functions")
	fmt.Println("• Command-line support via -insert-before and -insert-after flags")
	fmt.Println("• Automatic rule grouping is maintained after insertions")
}
