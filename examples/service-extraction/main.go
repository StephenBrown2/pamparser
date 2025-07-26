// Package main demonstrates service field population for pam.d format files.
package main

import (
	"fmt"
	"log"
	"strings"

	pp "github.com/StephenBrown2/pamparser"
)

func main() {
	// Example pam.d file content (like /etc/pam.d/sshd)
	pamdContent := `# PAM configuration for SSH daemon
auth       required     pam_unix.so
auth       required     pam_deny.so
account    required     pam_unix.so
password   required     pam_unix.so
session    required     pam_unix.so
session    optional     pam_motd.so`

	fmt.Println("=== Service Field Population Demo ===")
	fmt.Println()

	// Create parser
	parser := pp.NewParser()

	// Parse as pam.d format WITHOUT service name
	fmt.Println("1. Parsing pam.d format WITHOUT service name:")
	config1, err := parser.Parse(strings.NewReader(pamdContent), true)
	if err != nil {
		log.Fatalf("Failed to parse: %v", err)
	}

	for i, rule := range config1.Rules {
		fmt.Printf("   Rule %d: Service='%s', Type=%s, Module=%s\n",
			i+1, rule.Service, rule.Type, rule.ModulePath)
	}

	// Parse as pam.d format WITH service name
	fmt.Println("\n2. Parsing pam.d format WITH service name 'sshd':")
	config2, err := parser.ParseWithService(strings.NewReader(pamdContent), true, "sshd")
	if err != nil {
		log.Fatalf("Failed to parse: %v", err)
	}

	for i, rule := range config2.Rules {
		fmt.Printf("   Rule %d: Service='%s', Type=%s, Module=%s\n",
			i+1, rule.Service, rule.Type, rule.ModulePath)
	}

	// Demonstrate FileManager usage (simulated)
	fmt.Println("\n3. FileManager automatically extracts service name from pam.d paths:")

	testPaths := []string{
		"/etc/pam.d/sshd",
		"/etc/pam.d/sudo",
		"/usr/local/etc/pam.d/login",
	}

	for _, path := range testPaths {
		// Simulate the service extraction logic
		serviceName := ""
		if strings.Contains(path, "/pam.d/") {
			parts := strings.Split(path, "/pam.d/")
			if len(parts) > 1 {
				serviceName = parts[1]
			}
		}
		fmt.Printf("   Path: %s → Service: '%s'\n", path, serviceName)
	}

	fmt.Println("\n4. Usage with FileManager (when reading actual files):")
	fmt.Println("   fm := pp.NewFileManager()")
	fmt.Println("   config, err := fm.LoadFromFile(\"/etc/pam.d/sshd\")")
	fmt.Println("   // All rules will have Service field set to \"sshd\"")
}
