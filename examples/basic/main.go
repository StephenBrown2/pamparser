// Package main demonstrates basic usage of the PAM parser library,
// including parsing, editing, validation, and writing of PAM configuration files.
package main

import (
	"fmt"
	"log"
	"strings"

	pp "github.com/StephenBrown2/pamparser"
)

func main() {
	// Example 1: Parse a PAM configuration from string
	fmt.Println("=== Example 1: Parsing PAM configuration ===")

	pamConfig := `# PAM configuration for SSH
auth required pam_unix.so nullok
auth sufficient pam_ldap.so
account required pam_unix.so
session required pam_unix.so
`

	fm := pp.NewFileManager()
	config, err := fm.LoadFromString(pamConfig, true) // true = pam.d format
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	fmt.Printf("Parsed %d rules and %d comments\n", len(config.Rules), len(config.Comments))
	for i, rule := range config.Rules {
		fmt.Printf("Rule %d: %s %s %s\n", i+1, rule.Type, rule.ModulePath, strings.Join(rule.Arguments, " "))
	}

	// Example 2: Edit the configuration
	fmt.Println("\n=== Example 2: Editing PAM configuration ===")

	editor := pp.NewEditor(config)

	// Add a new rule
	newRule := pp.Rule{
		Type:       pp.ModuleTypeAuth,
		Control:    pp.Control{Simple: stringPtr(pp.ControlOptional)},
		ModulePath: "pam_google_authenticator.so",
		Comment:    "Two-factor authentication",
	}
	editor.AddRule(newRule)

	// Update an argument in the first rule
	err = editor.UpdateArgument(0, "use_first_pass", "")
	if err != nil {
		log.Printf("Warning: %v", err)
	}

	// Find all auth rules
	authRules := editor.FindRules(pp.FilterByType(pp.ModuleTypeAuth))
	fmt.Printf("Found %d auth rules\n", len(authRules))

	// Example 3: Complex control syntax
	fmt.Println("\n=== Example 3: Complex control syntax ===")

	complexRule := pp.Rule{
		Type: pp.ModuleTypeAuth,
		Control: pp.Control{
			Complex: map[pp.ReturnValue]any{
				pp.ReturnSuccess: pp.ActionOK,
				pp.ReturnDefault: pp.ActionBad,
			},
		},
		ModulePath: "pam_unix.so",
	}
	editor.AddRule(complexRule)

	// Example 4: Write the modified configuration
	fmt.Println("\n=== Example 4: Writing configuration ===")

	modifiedConfig := editor.GetConfig()
	output, err := fm.SaveToString(modifiedConfig)
	if err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}

	fmt.Println("Modified configuration:")
	fmt.Println(output)

	// Example 5: Validation
	fmt.Println("\n=== Example 5: Configuration validation ===")

	warnings := editor.Validate()
	if len(warnings) > 0 {
		fmt.Println("Validation warnings:")
		for _, warning := range warnings {
			fmt.Printf("- %s\n", warning)
		}
	} else {
		fmt.Println("Configuration is valid!")
	}

	// Example 6: Demonstrating different control types
	fmt.Println("\n=== Example 6: Different control types ===")

	examples := []pp.Rule{
		{
			Type:       pp.ModuleTypeAuth,
			Control:    pp.Control{Simple: stringPtr(pp.ControlRequired)},
			ModulePath: "pam_unix.so",
		},
		{
			Type:       pp.ModuleTypeAuth,
			Control:    pp.Control{Simple: stringPtr(pp.ControlRequisite)},
			ModulePath: "pam_deny.so",
		},
		{
			Type:       pp.ModuleTypeAuth,
			Control:    pp.Control{Simple: stringPtr(pp.ControlSufficient)},
			ModulePath: "pam_ldap.so",
		},
		{
			Type:       pp.ModuleTypeAuth,
			Control:    pp.Control{Simple: stringPtr(pp.ControlOptional), Optional: true},
			ModulePath: "pam_mount.so",
		},
		{
			Type:      pp.ModuleTypeAuth,
			Control:   pp.Control{Simple: stringPtr(pp.ControlInclude)},
			Arguments: []string{"common-auth"},
		},
	}

	writer := pp.NewWriter()
	for i, rule := range examples {
		output, writeErr := writer.WriteString(&pp.Config{Rules: []pp.Rule{rule}})
		if writeErr != nil {
			log.Printf("Error writing rule %d: %v", i, writeErr)
			continue
		}
		fmt.Printf("Example %d: %s", i+1, output)
	}

	// Example 7: Parse pam.conf format (with service field)
	fmt.Println("\n=== Example 7: PAM.conf format ===")

	pamConfContent := `# System-wide PAM configuration
login auth required pam_unix.so nullok
login account required pam_unix.so
su auth required pam_unix.so
su account required pam_unix.so
`

	pamConfConfig, err := fm.LoadFromString(pamConfContent, false) // false = pam.conf format
	if err != nil {
		log.Fatalf("Failed to parse pam.conf: %v", err)
	}

	fmt.Printf("Parsed pam.conf with %d rules\n", len(pamConfConfig.Rules))
	for _, rule := range pamConfConfig.Rules {
		fmt.Printf("Service: %s, Type: %s, Module: %s\n", rule.Service, rule.Type, rule.ModulePath)
	}

	// Example 8: Handling arguments with special characters
	fmt.Println("\n=== Example 8: Special arguments ===")

	specialRule := pp.Rule{
		Type:       pp.ModuleTypeAuth,
		Control:    pp.Control{Simple: stringPtr(pp.ControlRequired)},
		ModulePath: "pam_mysql.so",
		Arguments: []string{
			"user=pam",
			"passwd=secret",
			"host=localhost",
			"db=pam",
			"table=users",
			"query=SELECT user FROM users WHERE user='%u' AND password=PASSWORD('%p')",
		},
	}

	specialConfig := &pp.Config{Rules: []pp.Rule{specialRule}}
	specialOutput, err := writer.WriteString(specialConfig)
	if err != nil {
		log.Fatalf("Failed to write special config: %v", err)
	}

	fmt.Println("Rule with special arguments:")
	fmt.Print(specialOutput)

	// Parse it back to verify round-trip
	parsedBack, err := fm.LoadFromString(specialOutput, true)
	if err != nil {
		log.Fatalf("Failed to parse back: %v", err)
	}

	if len(parsedBack.Rules) != 1 {
		log.Fatalf("Expected 1 rule after round-trip, got %d", len(parsedBack.Rules))
	}

	fmt.Printf("Round-trip successful! Parsed %d arguments\n", len(parsedBack.Rules[0].Arguments))
}

// Helper function to create pointer to ControlType
func stringPtr(ct pp.ControlType) *pp.ControlType {
	return &ct
}
