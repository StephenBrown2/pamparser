# PAM Parser - Go Library for Linux PAM Configuration

A comprehensive Go library for parsing, editing, and writing Linux PAM (Pluggable Authentication Modules) configuration files. This library supports both `/etc/pam.conf` format (with service field) and `/etc/pam.d/*` format (without service field).

## Features

- **Parse PAM configurations** from files, strings, or readers
- **Edit configurations** programmatically with a fluent API
- **Write configurations** back to files or strings
- **Validate configurations** for common issues
- **Support both formats**: `/etc/pam.conf` and `/etc/pam.d/*`
- **Handle complex control syntax** like `[success=ok default=bad]`
- **Parse module arguments** with proper escaping for brackets
- **Line continuation** support with `\` character
- **Comment preservation** for both inline and standalone comments
- **File backup and restore** functionality
- **Command-line tool** for common operations

## Installation

```bash
go get github.com/StephenBrown2/pamparser
```

## Quick Start

### Parsing a PAM Configuration

```go
package main

import (
    "fmt"
    "log"
    pp "github.com/StephenBrown2/pamparser"
)

func main() {
    pamConfig := `# SSH PAM configuration
auth required pam_unix.so nullok
auth sufficient pam_ldap.so
account required pam_unix.so
session required pam_unix.so
`

    fm := pp.NewFileManager()
    config, err := fm.LoadFromString(pamConfig, true) // true = pam.d format
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Parsed %d rules\n", len(config.Rules))
    for _, rule := range config.Rules {
        fmt.Printf("%s %s %s\n", rule.Type, rule.Control, rule.ModulePath)
    }
}
```

### Editing a Configuration

```go
editor := pp.NewEditor(config)

// Add a new rule
newRule := pp.Rule{
    Type:       pp.ModuleTypeAuth,
    Control:    pp.Control{Simple: &pp.ControlOptional},
    ModulePath: "pam_google_authenticator.so",
    Comment:    "Two-factor authentication",
}
editor.AddRule(newRule)

// Find and remove LDAP rules
ldapRules := editor.FindRules(pp.FilterByModulePath("ldap"))
for _, index := range ldapRules {
    editor.RemoveRule(index)
}

// Update arguments
editor.UpdateArgument(0, "use_first_pass", "")
```

### Writing Configuration

```go
writer := pp.NewWriter()
output, err := writer.WriteString(config)
if err != nil {
    log.Fatal(err)
}
fmt.Print(output)
```

## Core Types

### Rule

Represents a single PAM configuration rule:

```go
type Rule struct {
    Service     string       // Only present in /etc/pam.conf format
    Type        ModuleType   // auth, account, password, session
    Control     Control      // required, optional, [complex syntax]
    ModulePath  string       // Path to the PAM module
    Arguments   []string     // Module arguments
    Comment     string       // Inline comment
    LineNumber  int          // Original line number
    Continuation bool        // True if line uses continuation
}
```

### Control

Represents PAM control field (simple or complex):

```go
type Control struct {
    Simple   *ControlType                // Simple: required, optional, etc.
    Complex  map[ReturnValue]interface{} // Complex: [success=ok default=bad]
    Optional bool                        // True if prepended with '-', the PAM library will not log to the system log if it is not possible to load the module because it is missing in the system
}
```

### Module Types

```go
const (
    ModuleTypeAccount  ModuleType = "account"
    ModuleTypeAuth     ModuleType = "auth"
    ModuleTypePassword ModuleType = "password"
    ModuleTypeSession  ModuleType = "session"
)
```

### Control Types

```go
const (
    ControlRequired   ControlType = "required"
    ControlRequisite  ControlType = "requisite"
    ControlSufficient ControlType = "sufficient"
    ControlOptional   ControlType = "optional"
    ControlInclude    ControlType = "include"
    ControlSubstack   ControlType = "substack"
)
```

## Advanced Usage

### Complex Control Syntax

```go
// Parse complex control like [success=ok new_authtok_reqd=ok default=bad]
complexControl := pp.Control{
    Complex: map[pp.ReturnValue]interface{}{
        pp.ReturnSuccess:        pp.ActionOK,
        pp.ReturnNewAuthtokReqd: pp.ActionOK,
        pp.ReturnDefault:        pp.ActionBad,
    },
}

rule := pp.Rule{
    Type:       pp.ModuleTypeAuth,
    Control:    complexControl,
    ModulePath: "pam_unix.so",
}
```

### Filtering Rules

```go
editor := pp.NewEditor(config)

// Find rules by service
loginRules := editor.FindRules(pp.FilterByService("login"))

// Find rules by type
authRules := editor.FindRules(pp.FilterByType(pp.ModuleTypeAuth))

// Find rules by module path
unixRules := editor.FindRules(pp.FilterByModulePath("pam_unix"))

// Combine filters
sshAuthRules := editor.FindRules(pp.CombineFilters(
    pp.FilterByService("sshd"),
    pp.FilterByType(pp.ModuleTypeAuth),
))
```

### Handling Arguments with Special Characters

```go
// Arguments with spaces or brackets are automatically escaped
rule := pp.Rule{
    Type:       pp.ModuleTypeAuth,
    Control:    pp.Control{Simple: &pp.ControlRequired},
    ModulePath: "pam_mysql.so",
    Arguments: []string{
        "user=pam",
        "passwd=secret",
        "query=SELECT user FROM users WHERE user='%u'",
    },
}

// When written, special arguments will be wrapped in brackets:
// auth required pam_mysql.so user=pam passwd=secret [query=SELECT user FROM users WHERE user='%u']
```

### File Operations

```go
fm := pp.NewFileManager()

// Load from file
config, err := fm.LoadFromFile("/etc/pam.d/sshd")

// Create backup
backupPath, err := fm.BackupFile("/etc/pam.d/sshd")

// Save changes
err = fm.SaveToFile(config, "/etc/pam.d/sshd")

// Restore from backup if needed
err = fm.RestoreFromBackup("/etc/pam.d/sshd")

// Validate configuration
warnings := editor.Validate()
```

## Command Line Tool

The library includes a command-line tool for common operations:

```bash
# List rules in a file
pam-tool -file /etc/pam.d/sshd -list

# Validate a configuration
pam-tool -file /etc/pam.d/sshd -validate

# Add a new rule with backup
pam-tool -file /etc/pam.d/sshd -backup -add-rule 'auth required pam_unix.so nullok'

# Remove all LDAP rules
pam-tool -file /etc/pam.d/sshd -remove-rule '::pam_ldap'

# Create a new configuration
pam-tool -pamd -add-rule 'auth required pam_unix.so' -output new-config
```

## Examples

### Complete Example: SSH Configuration Management

```go
package main

import (
    "fmt"
    "log"
    pp "github.com/StephenBrown2/pamparser"
)

func main() {
    fm := pp.NewFileManager()

    // Load existing SSH PAM configuration
    config, err := fm.LoadFromFile("/etc/pam.d/sshd")
    if err != nil {
        log.Fatal(err)
    }

    editor := pp.NewEditor(config)

    // Add two-factor authentication
    mfaRule := pp.Rule{
        Type:       pp.ModuleTypeAuth,
        Control:    pp.Control{Simple: &pp.ControlRequired},
        ModulePath: "pam_google_authenticator.so",
        Comment:    "Google Authenticator MFA",
    }

    // Insert MFA rule before the first auth rule
    authRules := editor.FindRules(pp.FilterByType(pp.ModuleTypeAuth))
    if len(authRules) > 0 {
        editor.InsertRule(authRules[0], mfaRule)
    } else {
        editor.AddRule(mfaRule)
    }

    // Validate the configuration
    warnings := editor.Validate()
    if len(warnings) > 0 {
        fmt.Println("Warnings:")
        for _, warning := range warnings {
            fmt.Printf("  %s\n", warning)
        }
    }

    // Create backup and save
    backupPath, err := fm.BackupFile("/etc/pam.d/sshd")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created backup: %s\n", backupPath)

    modifiedConfig := editor.GetConfig()
    err = fm.SaveToFile(modifiedConfig, "/etc/pam.d/sshd")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("SSH PAM configuration updated successfully")
}
```

## PAM Configuration Format Reference

### Basic Rule Format

**PAM.conf format** (with service field):

```pam
service type control module-path module-arguments
```

**PAM.d format** (without service field):

```pam
type control module-path module-arguments
```

### Module Types

- `auth` - Authentication and credential granting
- `account` - Account management and access control
- `password` - Password/authentication token update
- `session` - Session management

### Control Values

**Simple Control:**

- `required` - Must succeed, but continue processing
- `requisite` - Must succeed, stop processing on failure
- `sufficient` - Success stops processing, failure is ignored
- `optional` - Only matters if it's the only module
- `include` - Include another configuration file
- `substack` - Include as a substack

**Complex Control:**

```control
[return_value=action return_value=action ...]
```

**Return Values:**

- `success`, `auth_err`, `cred_insufficient`, `user_unknown`, etc.

**Actions:**

- `ignore` - Ignore return code
- `bad` - Treat as failure
- `die` - Treat as failure and stop
- `ok` - Use return code directly
- `done` - Use return code and stop
- `reset` - Reset module stack state
- `N` (number) - Jump N modules

### Line Continuation

Use backslash `\` at end of line:

```pam
auth required pam_mysql.so user=test passwd=secret \
    db=testdb query=select user from users
```

### Comments

```pam
# This is a comment
auth required pam_unix.so  # Inline comment
```

### Arguments with Special Characters

```pam
auth required pam_mysql.so [query=SELECT * FROM users WHERE name='%u']
```

## Testing

Run the test suite:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [Linux PAM Documentation](http://www.linux-pp.org/documentation/)
- [PAM Configuration File Syntax](http://www.linux-pp.org/Linux-PAM-html/sag-configuration-file.html)
- [PAM Module Writers' Guide](http://www.linux-pp.org/Linux-PAM-html/mwg-introduction.html)
