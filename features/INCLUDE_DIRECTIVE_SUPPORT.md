# PAM Include Directive Support

## Summary

Successfully implemented comprehensive support for PAM `@include` directives in the Go PAM parser library. This addresses the real-world compatibility issues identified by the user when parsing PAM configuration files that use include directives.

## What Was Implemented

### 1. Parser Enhancements
- **New Rule Structure**: Extended the `Rule` struct to support directives with new fields:
  - `IsDirective bool` - Identifies directive vs regular rules
  - `DirectiveType string` - Type of directive (e.g., "include")
  - `DirectiveTarget string` - Target of directive (e.g., "common-auth")

- **Directive Parsing**: Added `parseDirective()` method that:
  - Recognizes `@include` syntax
  - Parses the target file name
  - Preserves comments and additional arguments
  - Validates directive structure

- **Integration**: Modified `parseLine()` to detect `@` prefix and route to directive parsing

### 2. Writer Enhancements
- **Directive Formatting**: Updated `formatRule()` method to handle directives separately from regular PAM rules
- **Proper Output**: Ensures directives are written back as `@include target # comment` format
- **Rule Ordering**: Modified `sortRulesByType()` to properly handle directives (preserve their order at end)

### 3. Editor Enhancements
- **Validation Updates**: Modified `Validate()` method to:
  - Skip regular rule validation for directives
  - Add directive-specific validation (missing type, missing target)
  - Prevent false positive validation errors

- **Rule Management**: Updated `AddRule()` to handle directives appropriately (append at end)
- **Deep Copy Fix**: Fixed `GetConfig()` to properly copy directive fields during deep copy operations

### 4. Comprehensive Testing
- **Parser Tests**: Verified parsing of various `@include` scenarios
- **Writer Tests**: Confirmed proper formatting and round-trip capability
- **Real-World Tests**: Tested with actual PAM file structures like `/etc/pam.d/sudo`
- **Editor Tests**: Validated adding, finding, and managing directive rules

## Real-World Impact

### Before Implementation
```
$ go run main.go
Error: invalid module type '@include' at line 4
```

### After Implementation
```
$ go run main.go
Successfully parsed PAM file with 5 rules (3 includes)
Found include directives:
  - @include common-auth
  - @include common-account
  - @include common-session-noninteractive
Validation results: 0 issues
```

## Features Supported

1. **Parsing**: Correctly parses `@include filename` directives
2. **Comments**: Preserves inline comments with directives
3. **Writing**: Formats directives back to proper PAM syntax
4. **Validation**: Validates directive structure without false errors
5. **Editing**: Add, remove, and find directive rules programmatically
6. **Round-trip**: Parse → Edit → Write maintains directive integrity

## Examples of Supported Syntax

```bash
# Simple include
@include common-auth

# Include with comment
@include common-account # Account management rules

# Multiple includes in typical PAM file
@include common-auth
@include common-account
@include common-session-noninteractive
```

## Files Modified

1. **parser.go**: Added directive parsing capability
2. **writer.go**: Added directive formatting support
3. **editor.go**: Updated validation and rule management
4. **Tests**: Added comprehensive test coverage for directives

## Backward Compatibility

All existing functionality remains fully compatible. Regular PAM rules continue to work exactly as before, with directives being an additive feature.

## Test Coverage

- ✅ All existing tests continue to pass (100% backward compatibility)
- ✅ New directive-specific tests added and passing
- ✅ Real-world PAM file structures tested and working
- ✅ Round-trip parsing/writing verified
- ✅ Validation logic properly handles directives

This implementation successfully resolves the real-world PAM parsing issues identified by the user and provides full support for PAM include directives while maintaining complete backward compatibility.
