# PAM Parser Library Examples

This document provides practical examples of using the PAM Parser library.

## Basic Parsing

### Parse a PAM.d file

```go
package main

import (
    "fmt"
    "log"
    pp "github.com/StephenBrown2/pamparser"
)

func main() {
    fm := pp.NewFileManager()
    config, err := fm.LoadFromFile("/etc/pam.d/sshd")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Loaded %d rules\n", len(config.Rules))
}
```

### Parse a PAM.conf file

```go
fm := pp.NewFileManager()
config, err := fm.LoadFromFile("/etc/pam.conf")
if err != nil {
    log.Fatal(err)
}

// config.IsPamD will be false for pam.conf format
fmt.Printf("Format: %s\n", map[bool]string{true: "pam.d", false: "pam.conf"}[config.IsPamD])
```

## Editing Configurations

### Add Authentication Rules

```go
editor := pp.NewEditor(config)

// Add Google Authenticator for 2FA
mfaRule := pp.Rule{
    Type:       pp.ModuleTypeAuth,
    Control:    pp.Control{Simple: &pp.ControlRequired},
    ModulePath: "pam_google_authenticator.so",
    Comment:    "Two-factor authentication",
}
editor.AddRule(mfaRule)

// Add optional LDAP authentication
ldapRule := pp.Rule{
    Type:       pp.ModuleTypeAuth,
    Control:    pp.Control{Simple: &pp.ControlOptional, Optional: true},
    ModulePath: "pam_ldap.so",
    Arguments:  []string{"use_first_pass"},
}
editor.AddRule(ldapRule)
```

### Complex Control Syntax

```go
// Equivalent to [success=ok new_authtok_reqd=ok default=bad]
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
    Arguments:  []string{"nullok"},
}
```

### Jump Actions

```go
// Jump 2 modules on success: [success=2 default=ignore]
jumpControl := pp.Control{
    Complex: map[pp.ReturnValue]interface{}{
        pp.ReturnSuccess: 2,  // Jump 2 modules
        pp.ReturnDefault: pp.ActionIgnore,
    },
}
```

## Filtering and Searching

### Find Rules by Type

```go
editor := pp.NewEditor(config)

// Find all authentication rules
authRules := editor.FindRules(pp.FilterByType(pp.ModuleTypeAuth))
fmt.Printf("Found %d auth rules\n", len(authRules))

// Find all session rules
sessionRules := editor.FindRules(pp.FilterByType(pp.ModuleTypeSession))
```

### Find Rules by Module

```go
// Find all Unix module rules
unixRules := editor.FindRules(pp.FilterByModulePath("pam_unix"))

// Find LDAP rules
ldapRules := editor.FindRules(pp.FilterByModulePath("ldap"))
```

### Combined Filters

```go
// Find SSH auth rules (for pam.conf format)
sshdAuthRules := editor.FindRules(pp.CombineFilters(
    pp.FilterByService("sshd"),
    pp.FilterByType(pp.ModuleTypeAuth),
))

// Find optional rules
optionalFilter := func(rule pp.Rule) bool {
    return rule.Control.Optional
}

optionalRules := editor.FindRules(optionalFilter)
```

## Modifying Rules

### Update Module Arguments

```go
// Find Unix auth rules and update arguments
unixAuthRules := editor.FindRules(pp.CombineFilters(
    pp.FilterByType(pp.ModuleTypeAuth),
    pp.FilterByModulePath("pam_unix"),
))

for _, ruleIndex := range unixAuthRules {
    // Add use_first_pass argument
    editor.UpdateArgument(ruleIndex, "use_first_pass", "")

    // Set minimum password length
    editor.UpdateArgument(ruleIndex, "minlen", "8")
}
```

### Change Control Types

```go
// Change optional rules to required
optionalRules := editor.FindRules(func(rule pp.Rule) bool {
    return rule.Control.Simple != nil && *rule.Control.Simple == pp.ControlOptional
})

for _, ruleIndex := range optionalRules {
    newControl := pp.Control{Simple: &pp.ControlRequired}
    editor.SetControl(ruleIndex, newControl)
}
```

### Remove Rules

```go
// Remove all LDAP rules
editor.RemoveRules(pp.FilterByModulePath("ldap"))

// Remove specific rule by index
editor.RemoveRule(0)
```

## Advanced Argument Handling

### Arguments with Special Characters

```go
rule := pp.Rule{
    Type:       pp.ModuleTypeAuth,
    Control:    pp.Control{Simple: &pp.ControlRequired},
    ModulePath: "pam_mysql.so",
    Arguments: []string{
        "user=pam",
        "passwd=secret",
        "host=localhost",
        "db=auth",
        "query=SELECT user FROM users WHERE user='%u' AND password=PASSWORD('%p')",
    },
}

// The query argument will be automatically bracketed when written:
// auth required pam_mysql.so user=pam passwd=secret host=localhost db=auth [query=SELECT user FROM users WHERE user='%u' AND password=PASSWORD('%p')]
```

### Parsing Bracketed Arguments

```go
// This input will be parsed correctly:
input := `auth required pam_mysql.so user=test [query=SELECT * FROM users WHERE name='test'] debug`

config, err := fm.LoadFromString(input, true)
if err != nil {
    log.Fatal(err)
}

rule := config.Rules[0]
// rule.Arguments will be: ["user=test", "query=SELECT * FROM users WHERE name='test'", "debug"]
```

## File Operations

### Backup and Restore

```go
fm := pp.NewFileManager()

// Create backup before modifying
backupPath, err := fm.BackupFile("/etc/pam.d/sshd")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Backup created: %s\n", backupPath)

// Make changes...
config, _ := fm.LoadFromFile("/etc/pam.d/sshd")
editor := pp.NewEditor(config)
// ... edit config ...

// Save changes
err = fm.SaveToFile(editor.GetConfig(), "/etc/pam.d/sshd")
if err != nil {
    // Restore from backup on error
    fm.RestoreFromBackup("/etc/pam.d/sshd")
    log.Fatal(err)
}
```

### Validation

```go
editor := pp.NewEditor(config)
warnings := editor.Validate()

if len(warnings) > 0 {
    fmt.Println("Configuration warnings:")
    for _, warning := range warnings {
        fmt.Printf("  - %s\n", warning)
    }
}
```

## Writing Configurations

### Custom Formatting

```go
writer := pp.NewWriter()
writer.MaxLineLength = 120  // Longer lines before continuation

// Write to string
output, err := writer.WriteString(config)
if err != nil {
    log.Fatal(err)
}
fmt.Print(output)

// Write to file
err = writer.Write(config, file)
```

### Line Continuation

```go
// Long rules will automatically use line continuation:
longRule := pp.Rule{
    Type:       pp.ModuleTypeAuth,
    Control:    pp.Control{Simple: &pp.ControlRequired},
    ModulePath: "pam_mysql.so",
    Arguments: []string{
        "user=pamuser",
        "passwd=secret",
        "host=localhost",
        "db=authentication",
        "table=users",
        "query=SELECT username FROM users WHERE username='%u' AND password=PASSWORD('%p') AND active=1",
    },
}

// Output will be:
// auth required pam_mysql.so user=pamuser passwd=secret host=localhost \
//     db=authentication table=users \
//     [query=SELECT username FROM users WHERE username='%u' AND password=PASSWORD('%p') AND active=1]
```

## Real-world Examples

### SSH Hardening

```go
func hardenSSH(configPath string) error {
    fm := pp.NewFileManager()

    // Load existing config
    config, err := fm.LoadFromFile(configPath)
    if err != nil {
        return err
    }

    editor := pp.NewEditor(config)

    // Add fail2ban integration
    fail2banRule := pp.Rule{
        Type:       pp.ModuleTypeAuth,
        Control:    pp.Control{Simple: &pp.ControlRequired},
        ModulePath: "pam_abl.so",
        Arguments:  []string{"config=/etc/security/pam_abl.conf"},
    }

    // Insert at the beginning
    editor.InsertRule(0, fail2banRule)

    // Add Google Authenticator after Unix auth
    unixAuthRules := editor.FindRules(pp.CombineFilters(
        pp.FilterByType(pp.ModuleTypeAuth),
        pp.FilterByModulePath("pam_unix"),
    ))

    if len(unixAuthRules) > 0 {
        mfaRule := pp.Rule{
            Type:       pp.ModuleTypeAuth,
            Control:    pp.Control{Simple: &pp.ControlRequired},
            ModulePath: "pam_google_authenticator.so",
        }
        editor.InsertRule(unixAuthRules[0]+1, mfaRule)
    }

    // Create backup and save
    backupPath, err := fm.BackupFile(configPath)
    if err != nil {
        return err
    }
    fmt.Printf("Backup created: %s\n", backupPath)

    return fm.SaveToFile(editor.GetConfig(), configPath)
}
```

### Password Policy Enforcement

```go
func enforcePasswordPolicy() pp.Rule {
    return pp.Rule{
        Type:       pp.ModuleTypePassword,
        Control:    pp.Control{Simple: &pp.ControlRequired},
        ModulePath: "pam_pwquality.so",
        Arguments: []string{
            "retry=3",
            "minlen=12",
            "difok=3",
            "ucredit=-1",  // At least 1 uppercase
            "lcredit=-1",  // At least 1 lowercase
            "dcredit=-1",  // At least 1 digit
            "ocredit=-1",  // At least 1 special char
        },
    }
}
```

This covers the main use cases and patterns for the PAM Parser library. The library provides a complete solution for programmatically managing PAM configurations in Go applications.
