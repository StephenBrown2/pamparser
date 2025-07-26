# New Feature: Pattern-Based Rule Insertion

## Overview

Added fine-grained rule insertion capabilities that allow inserting PAM rules before or after other rules based on flexible pattern matching.

## New API Methods

### `InsertRuleBefore(rule Rule, filter RuleFilter) error`

Inserts a rule before the **first** rule that matches the filter pattern.

### `InsertRuleAfter(rule Rule, filter RuleFilter) error`

Inserts a rule after the **last** rule that matches the filter pattern.

## Pattern Matching

Uses the existing `RuleFilter` system with flexible matching options:

- **By Module Type**: `FilterByType(ModuleTypeAuth)`
- **By Module Path**: `FilterByModulePath("pam_unix")`
- **By Service**: `FilterByService("sshd")`
- **By Control**: `FilterByControl(ControlRequired)`
- **Combined Filters**: `CombineFilters(filter1, filter2, ...)`

## Command-Line Interface

### New Flags

```bash
-insert-before string    Insert rule before matching pattern (format: 'rule|pattern')
-insert-after string     Insert rule after matching pattern (format: 'rule|pattern')
```

### Syntax Format

```
'rule|pattern'
```

Where:

- **rule**: `'type control module args...'` (same as -add-rule)
- **pattern**: `'service:type:module'` (same as -remove-rule filter)

### Examples

```bash
# Insert requisite rule before all pam_unix rules
pam-tool -file /etc/pam.d/sshd -insert-before 'auth requisite pam_nologin.so|::pam_unix'

# Insert optional rule after all auth rules
pam-tool -file /etc/pam.d/sshd -insert-after 'auth optional pam_krb5.so|:auth:'

# Insert before specific service rules (pam.conf format)
pam-tool -file /etc/pam.conf -insert-before 'auth required pam_securetty.so|login::'
```

## Use Cases

### 1. **Security Hardening**

```go
// Insert security check before authentication
editor.InsertRuleBefore(
    Rule{Type: ModuleTypeAuth, Control: Control{Simple: &ControlRequisite}, ModulePath: "pam_securetty.so"},
    FilterByType(ModuleTypeAuth)
)
```

### 2. **Service-Specific Rules**

```go
// Insert service-specific rule after existing auth rules
editor.InsertRuleAfter(
    Rule{Type: ModuleTypeAuth, Control: Control{Simple: &ControlOptional}, ModulePath: "pam_krb5.so"},
    FilterByType(ModuleTypeAuth)
)
```

### 3. **Module Ordering**

```go
// Insert prerequisite module before specific module
editor.InsertRuleBefore(
    Rule{Type: ModuleTypeSession, Control: Control{Simple: &ControlRequired}, ModulePath: "pam_systemd.so"},
    FilterByModulePath("pam_motd")
)
```

## Error Handling

- Returns error if no rules match the pattern
- Validates rule syntax before insertion
- Preserves automatic rule grouping after insertion

## Integration with Existing Features

- ✅ **Automatic Grouping**: Rules maintain proper type-based grouping
- ✅ **Rule Validation**: All validation rules still apply
- ✅ **Complex Controls**: Supports all PAM control syntax
- ✅ **Argument Handling**: Proper escaping and bracket handling
- ✅ **File Formats**: Works with both pam.conf and pam.d formats

## Testing

Comprehensive test coverage for:

- Insert before first matching rule
- Insert after last matching rule
- Error handling for non-matching patterns
- Integration with automatic grouping
- Command-line interface parsing

This feature provides the precision control needed for complex PAM configuration management while maintaining the library's commitment to proper PAM syntax and organization.
