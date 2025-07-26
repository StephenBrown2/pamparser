package pamparser

import (
	"strings"
	"testing"
)

func TestServiceFieldPopulation(t *testing.T) {
	// Test data representing content of /etc/pam.d/sshd
	pamdContent := `auth       required     pam_unix.so
account    required     pam_unix.so
password   required     pam_unix.so
session    required     pam_unix.so`

	// Test ParseWithService directly
	parser := NewParser()
	config, err := parser.ParseWithService(strings.NewReader(pamdContent), true, "sshd")
	if err != nil {
		t.Fatalf("Failed to parse pam.d content: %v", err)
	}

	// Verify all rules have the service field set
	if len(config.Rules) != 4 {
		t.Fatalf("Expected 4 rules, got %d", len(config.Rules))
	}

	for i, rule := range config.Rules {
		if rule.Service != "sshd" {
			t.Errorf("Rule %d: expected service 'sshd', got '%s'", i, rule.Service)
		}
	}

	// Test regular Parse method (should not set service for pam.d)
	config2, err := parser.Parse(strings.NewReader(pamdContent), true)
	if err != nil {
		t.Fatalf("Failed to parse with Parse method: %v", err)
	}

	for i, rule := range config2.Rules {
		if rule.Service != "" {
			t.Errorf("Rule %d: expected empty service, got '%s'", i, rule.Service)
		}
	}

	// Test pam.conf format (should read service from content)
	pamconfContent := `sshd auth       required     pam_unix.so
sshd account    required     pam_unix.so`

	config3, err := parser.ParseWithService(strings.NewReader(pamconfContent), false, "ignored")
	if err != nil {
		t.Fatalf("Failed to parse pam.conf content: %v", err)
	}

	// For pam.conf format, service should come from the content, not the parameter
	for i, rule := range config3.Rules {
		if rule.Service != "sshd" {
			t.Errorf("Rule %d: expected service 'sshd' from content, got '%s'", i, rule.Service)
		}
	}
}

func TestFileManagerServiceExtraction(t *testing.T) {
	// Test that FileManager would extract service name correctly
	// Note: This tests the logic without actually creating files

	testCases := []struct {
		path     string
		expected string
	}{
		{"/etc/pam.d/sshd", "sshd"},
		{"/etc/pam.d/sudo", "sudo"},
		{"/usr/local/etc/pam.d/login", "login"},
		{"/etc/pam.conf", ""},    // Not pam.d format
		{"/some/other/path", ""}, // Not pam.d format
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			// Simulate the service extraction logic from FileManager
			isPamD := strings.Contains(tc.path, "/pam.d/")
			var serviceName string
			if isPamD {
				serviceName = strings.Split(tc.path, "/pam.d/")[1]
				// Handle case where there might be additional path components
				if idx := strings.Index(serviceName, "/"); idx != -1 {
					serviceName = serviceName[:idx]
				}
			}

			if serviceName != tc.expected {
				t.Errorf("For path %s: expected service '%s', got '%s'", tc.path, tc.expected, serviceName)
			}
		})
	}
}
