# PAM Parser Examples

This directory contains examples demonstrating various features of the PAM configuration parser library.

## Available Examples

### 1. Basic Usage (`basic/`)

Demonstrates the fundamental functionality of the PAM parser:

- Parsing PAM configuration files
- Writing configurations back to files
- Basic error handling

**Run with:**

```bash
go run examples/basic/main.go
```

### 2. Rule Grouping (`grouping/`)

Demonstrates the automatic rule grouping feature:

- Parsing unsorted PAM configurations
- Automatic grouping by module type (account, auth, password, session)
- Adding new rules with intelligent positioning
- Maintaining proper PAM file organization

**Run with:**

```bash
go run examples/grouping/main.go
```

### 3. Pattern-Based Rule Insertion (`insertion/`)

Demonstrates advanced rule insertion capabilities:

- Inserting rules before/after specific patterns
- Using flexible pattern matching with RuleFilter functions
- Error handling for non-matching patterns
- Maintaining automatic grouping after insertions

**Run with:**

```bash
go run examples/insertion/main.go
```

## Common Use Cases Covered

1. **Basic PAM Management**: Parse, modify, and write PAM configurations
2. **Configuration Organization**: Automatic rule grouping by type
3. **Precise Rule Placement**: Insert rules at specific positions using patterns
4. **Validation**: Proper PAM syntax validation and error handling
5. **Format Support**: Both `/etc/pam.conf` and `/etc/pam.d/*` formats

## Example Output

Each example produces detailed output showing:

- Original configuration
- Step-by-step transformations
- Final result
- Summary of operations performed

## Getting Started

To run any example:

1. Make sure you're in the project root directory
2. Run the desired example using `go run examples/{example-name}/main.go`
3. Review the output to understand the demonstrated features

For more information about the PAM parser library, see the main project documentation.
