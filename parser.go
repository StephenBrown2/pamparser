// Package pamparser provides functionality to parse, edit, and write Linux PAM configuration files.
// It supports both /etc/pam.conf format (with service field) and /etc/pam.d/* format (without service field).
package pamparser

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ModuleType represents the PAM module type
type ModuleType string

const (
	// ModuleTypeAccount represents the account module type for account verification
	ModuleTypeAccount ModuleType = "account"
	// ModuleTypeAuth represents the auth module type for authentication
	ModuleTypeAuth ModuleType = "auth"
	// ModuleTypePassword represents the password module type for password management
	ModuleTypePassword ModuleType = "password"
	// ModuleTypeSession represents the session module type for session management
	ModuleTypeSession ModuleType = "session"
	// ModuleTypeSessionNoninteractive represents the session-noninteractive module type for non-interactive session management
	ModuleTypeSessionNoninteractive ModuleType = "session-noninteractive"
)

// ControlType represents the basic control keywords
type ControlType string

const (
	// ControlRequired means success of this module is required for overall success
	ControlRequired ControlType = "required"
	// ControlRequisite means failure of this module will cause immediate failure
	ControlRequisite ControlType = "requisite"
	// ControlSufficient means success of this module is sufficient for overall success
	ControlSufficient ControlType = "sufficient"
	// ControlOptional means this module's result does not affect overall success
	ControlOptional ControlType = "optional"
	// ControlInclude means include another PAM configuration file
	ControlInclude ControlType = "include"
	// ControlSubstack means push the current PAM stack and invoke a substack
	ControlSubstack ControlType = "substack"
)

// ActionType represents actions in complex control syntax
type ActionType string

const (
	// ActionIgnore means ignore the result of this module
	ActionIgnore ActionType = "ignore"
	// ActionBad means treat the result as bad
	ActionBad ActionType = "bad"
	// ActionDie means treat the result as bad and abort the stack
	ActionDie ActionType = "die"
	// ActionOK means treat the result as good
	ActionOK ActionType = "ok"
	// ActionDone means treat the result as good and stop processing the stack
	ActionDone ActionType = "done"
	// ActionReset means reset the return value and continue
	ActionReset ActionType = "reset"
)

// ReturnValue represents PAM return codes
type ReturnValue string

const (
	// ReturnSuccess indicates successful completion
	ReturnSuccess ReturnValue = "success"
	// ReturnOpenErr indicates failure to load module
	ReturnOpenErr ReturnValue = "open_err"
	// ReturnSymbolErr indicates symbol not found
	ReturnSymbolErr ReturnValue = "symbol_err"
	// ReturnServiceErr indicates error in service module
	ReturnServiceErr ReturnValue = "service_err"
	// ReturnSystemErr indicates system error
	ReturnSystemErr ReturnValue = "system_err"
	// ReturnBufErr indicates memory buffer error
	ReturnBufErr ReturnValue = "buf_err"
	// ReturnPermDenied indicates permission denied
	ReturnPermDenied ReturnValue = "perm_denied"
	// ReturnAuthErr indicates authentication failure
	ReturnAuthErr ReturnValue = "auth_err"
	// ReturnCredInsufficient indicates insufficient credentials
	ReturnCredInsufficient ReturnValue = "cred_insufficient"
	// ReturnAuthinfoUnavail indicates authentication info unavailable
	ReturnAuthinfoUnavail ReturnValue = "authinfo_unavail"
	// ReturnUserUnknown indicates user unknown
	ReturnUserUnknown ReturnValue = "user_unknown"
	// ReturnMaxtries indicates maximum tries exceeded
	ReturnMaxtries ReturnValue = "maxtries"
	// ReturnNewAuthtokReqd indicates new authentication token required
	ReturnNewAuthtokReqd ReturnValue = "new_authtok_reqd"
	// ReturnAcctExpired indicates account expired
	ReturnAcctExpired ReturnValue = "acct_expired"
	// ReturnSessionErr indicates session failure
	ReturnSessionErr ReturnValue = "session_err"
	// ReturnCredUnavail indicates credentials unavailable
	ReturnCredUnavail ReturnValue = "cred_unavail"
	// ReturnCredExpired indicates credentials expired
	ReturnCredExpired ReturnValue = "cred_expired"
	// ReturnCredErr indicates credentials error
	ReturnCredErr ReturnValue = "cred_err"
	// ReturnNoModuleData indicates no module specific data
	ReturnNoModuleData ReturnValue = "no_module_data"
	// ReturnConvErr indicates conversation error
	ReturnConvErr ReturnValue = "conv_err"
	// ReturnAuthtokErr indicates authentication token manipulation error
	ReturnAuthtokErr ReturnValue = "authtok_err"
	// ReturnAuthtokRecoverErr indicates authentication token recovery error
	ReturnAuthtokRecoverErr ReturnValue = "authtok_recover_err"
	// ReturnAuthtokLockBusy indicates authentication token lock busy
	ReturnAuthtokLockBusy ReturnValue = "authtok_lock_busy"
	// ReturnAuthtokDisableAging indicates disable aging on authentication token
	ReturnAuthtokDisableAging ReturnValue = "authtok_disable_aging"
	// ReturnTryAgain indicates should try again later
	ReturnTryAgain ReturnValue = "try_again"
	// ReturnIgnore indicates ignore this return value
	ReturnIgnore ReturnValue = "ignore"
	// ReturnAbort indicates abort the authentication process
	ReturnAbort ReturnValue = "abort"
	// ReturnAuthtokExpired indicates authentication token expired
	ReturnAuthtokExpired ReturnValue = "authtok_expired"
	// ReturnModuleUnknown indicates module unknown
	ReturnModuleUnknown ReturnValue = "module_unknown"
	// ReturnBadItem indicates bad item passed to function
	ReturnBadItem ReturnValue = "bad_item"
	// ReturnConvAgain indicates conversation function should be called again
	ReturnConvAgain ReturnValue = "conv_again"
	// ReturnIncomplete indicates incomplete
	ReturnIncomplete ReturnValue = "incomplete"
	// ReturnDefault indicates default return value
	ReturnDefault ReturnValue = "default"
)

// Control represents either a simple control keyword or complex control syntax
type Control struct {
	Simple   *ControlType        `json:"simple,omitempty"`
	Complex  map[ReturnValue]any `json:"complex,omitempty"`  // any can be ActionType or int (for jump)
	Optional bool                `json:"optional,omitempty"` // true if prepended with '-'
}

// Rule represents a single PAM configuration rule or directive
type Rule struct {
	Control         Control    `json:"control,omitempty"`
	Service         string     `json:"service,omitempty"`
	Type            ModuleType `json:"type,omitempty"`
	ModulePath      string     `json:"module_path,omitempty"`
	Comment         string     `json:"comment,omitempty"`
	DirectiveType   string     `json:"directive_type,omitempty"`
	DirectiveTarget string     `json:"directive_target,omitempty"`
	Arguments       []string   `json:"arguments,omitempty"`
	LineNumber      int        `json:"line_number,omitempty"`
	Continuation    bool       `json:"continuation,omitempty"`
	IsDirective     bool       `json:"is_directive,omitempty"`
}

// Config represents a PAM configuration file
type Config struct {
	FilePath string   `json:"file_path,omitempty"`
	Rules    []Rule   `json:"rules"`
	Comments []string `json:"comments,omitempty"`
	IsPamD   bool     `json:"is_pam_d,omitempty"`
}

// Parser handles PAM configuration parsing
type Parser struct {
	// Regex patterns for parsing
	rulePattern     *regexp.Regexp
	commentPattern  *regexp.Regexp
	controlPattern  *regexp.Regexp
	argumentPattern *regexp.Regexp
}

// NewParser creates a new PAM configuration parser
func NewParser() *Parser {
	return &Parser{
		rulePattern:     regexp.MustCompile(`^\s*([^#\s]+)(?:\s+([^#\s]+))?(?:\s+([^#\s\[]+|\[[^\]]*\]))(?:\s+([^#\s]+))(?:\s+(.*))?(?:\s*#(.*))?$`),
		commentPattern:  regexp.MustCompile(`^\s*#(.*)$`),
		controlPattern:  regexp.MustCompile(`^\[([^\]]+)\]$`),
		argumentPattern: regexp.MustCompile(`\[([^\]]*)\]|([^\s\[]+)`),
	}
}

// IsValidModuleType checks if the given string is a valid module type
func IsValidModuleType(t string) bool {
	// Handle negative module types (e.g., -session, -auth)
	moduleType := strings.ToLower(t)
	moduleType = strings.TrimPrefix(moduleType, "-")

	switch ModuleType(moduleType) {
	case ModuleTypeAccount, ModuleTypeAuth, ModuleTypePassword, ModuleTypeSession, ModuleTypeSessionNoninteractive:
		return true
	default:
		return false
	}
}

// IsValidControlType checks if the given string is a valid simple control type
func IsValidControlType(c string) bool {
	switch ControlType(strings.ToLower(c)) {
	case ControlRequired, ControlRequisite, ControlSufficient, ControlOptional, ControlInclude, ControlSubstack:
		return true
	default:
		return false
	}
}

// GetModuleTypeOrder returns the standard ordering index for a module type
func GetModuleTypeOrder(moduleType ModuleType) int {
	// Handle negative module types by stripping the prefix for ordering
	typeStr := string(moduleType)
	typeStr = strings.TrimPrefix(typeStr, "-")

	switch ModuleType(typeStr) {
	case ModuleTypeAccount:
		return 0
	case ModuleTypeAuth:
		return 1
	case ModuleTypePassword:
		return 2
	case ModuleTypeSession:
		return 3
	case ModuleTypeSessionNoninteractive:
		return 4
	default:
		return 5 // Unknown types go last
	}
}

// GetNormalizedModuleType returns the base module type without negative prefix for grouping
func GetNormalizedModuleType(moduleType ModuleType) ModuleType {
	typeStr := string(moduleType)
	typeStr = strings.TrimPrefix(typeStr, "-")
	return ModuleType(typeStr)
}

// parseControl parses a control field which can be either simple or complex
func (p *Parser) parseControl(controlStr string) (Control, error) {
	control := Control{}

	// Check if it's optional (starts with -)
	optional := false
	if strings.HasPrefix(controlStr, "-") {
		optional = true
		controlStr = controlStr[1:]
	}

	// Check if it's complex control syntax [value=action ...]
	if p.controlPattern.MatchString(controlStr) {
		return p.parseComplexControl(controlStr, optional)
	}

	// Simple control
	controlType := ControlType(strings.ToLower(controlStr))
	if !IsValidControlType(string(controlType)) {
		return control, fmt.Errorf("invalid control type: %s", controlStr)
	}

	control.Simple = &controlType
	control.Optional = optional
	return control, nil
}

// parseComplexControl parses complex control syntax like [success=ok default=bad]
func (p *Parser) parseComplexControl(controlStr string, optional bool) (Control, error) {
	control := Control{
		Complex:  make(map[ReturnValue]any),
		Optional: optional,
	}

	// Remove brackets
	inner := strings.TrimPrefix(strings.TrimSuffix(controlStr, "]"), "[")

	// Split by spaces and parse value=action pairs
	pairs := strings.Fields(inner)
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return control, fmt.Errorf("invalid control pair: %s", pair)
		}

		returnVal := ReturnValue(parts[0])
		actionStr := parts[1]

		// Check if action is a number (jump)
		var jumpNum int
		if n, err := fmt.Sscanf(actionStr, "%d", &jumpNum); n == 1 && err == nil {
			control.Complex[returnVal] = jumpNum
		} else {
			// It's an action type
			action := ActionType(actionStr)
			control.Complex[returnVal] = action
		}
	}

	return control, nil
}

// parseArguments parses module arguments, handling square bracket escaping
func (p *Parser) parseArguments(argStr string) []string {
	if argStr == "" {
		return nil
	}

	var args []string
	i := 0
	argStr = strings.TrimSpace(argStr)

	for i < len(argStr) {
		// Skip whitespace
		for i < len(argStr) && (argStr[i] == ' ' || argStr[i] == '\t') {
			i++
		}
		if i >= len(argStr) {
			break
		}

		if argStr[i] == '[' {
			// Parse bracketed argument
			start := i + 1
			i++
			depth := 1

			for i < len(argStr) && depth > 0 {
				switch {
				case argStr[i] == '\\' && i+1 < len(argStr):
					// Skip escaped character
					i += 2
				case argStr[i] == '[':
					depth++
					i++
				case argStr[i] == ']':
					depth--
					i++
				default:
					i++
				}
			}

			if depth == 0 {
				// Extract the content inside brackets and unescape
				content := argStr[start : i-1]
				content = strings.ReplaceAll(content, `\]`, `]`)
				content = strings.ReplaceAll(content, `\[`, `[`)
				args = append(args, content)
			}
		} else {
			// Parse regular argument (until space or bracket)
			start := i
			for i < len(argStr) && argStr[i] != ' ' && argStr[i] != '\t' && argStr[i] != '[' {
				i++
			}
			if i > start {
				args = append(args, argStr[start:i])
			}
		}
	}

	return args
}

// parseDirective parses PAM directives like @include
func (p *Parser) parseDirective(tokens []string, rule *Rule, lineNum int) (*Rule, string, error) {
	if len(tokens) == 0 {
		return nil, "", fmt.Errorf("empty directive at line %d", lineNum)
	}

	directiveToken := tokens[0]
	if !strings.HasPrefix(directiveToken, "@") {
		return nil, "", fmt.Errorf("expected directive to start with @ at line %d", lineNum)
	}

	// Extract directive type (remove @)
	directiveType := strings.TrimPrefix(directiveToken, "@")

	// Set directive fields
	rule.IsDirective = true
	rule.DirectiveType = directiveType

	switch directiveType {
	case "include":
		if len(tokens) < 2 {
			return nil, "", fmt.Errorf("@include directive missing target at line %d", lineNum)
		}
		rule.DirectiveTarget = tokens[1]

		// Handle any additional arguments
		if len(tokens) > 2 {
			rule.Arguments = tokens[2:]
		}

	default:
		return nil, "", fmt.Errorf("unknown directive type '@%s' at line %d", directiveType, lineNum)
	}

	return rule, "", nil
}

// tokenizeLine splits a line into tokens, respecting brackets
func tokenizeLine(line string) []string {
	var tokens []string
	var current strings.Builder
	inBrackets := false

	for i, r := range line {
		switch r {
		case '[':
			if !inBrackets {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
				inBrackets = true
			}
			current.WriteRune(r)
		case ']':
			current.WriteRune(r)
			if inBrackets {
				tokens = append(tokens, current.String())
				current.Reset()
				inBrackets = false
			}
		case ' ', '\t':
			if inBrackets {
				current.WriteRune(r)
			} else if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		case '#':
			if !inBrackets {
				// Rest of line is comment
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
				}
				tokens = append(tokens, line[i:])
				return tokens
			}
			current.WriteRune(r)
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// parseLine parses a single line of PAM configuration
func (p *Parser) parseLine(line string, lineNum int, isPamD bool, serviceName string) (*Rule, string, error) {
	originalLine := line

	// Handle line continuation
	line = strings.TrimRight(line, " \t\n\r")
	continuation := strings.HasSuffix(line, "\\")
	if continuation {
		line = strings.TrimSuffix(line, "\\")
	}

	// Check for comment-only line
	if commentMatch := p.commentPattern.FindStringSubmatch(originalLine); commentMatch != nil {
		return nil, strings.TrimSpace(commentMatch[1]), nil
	}

	// Skip empty lines
	if strings.TrimSpace(line) == "" {
		return nil, "", nil
	}

	// Parse rule line
	rule := Rule{
		LineNumber:   lineNum,
		Continuation: continuation,
	}

	// Set service name for pam.d format files
	if isPamD && serviceName != "" {
		rule.Service = serviceName
	}

	// Tokenize line properly, respecting brackets
	tokens := tokenizeLine(line)
	if len(tokens) == 0 {
		return nil, "", fmt.Errorf("empty rule at line %d", lineNum)
	}

	// Handle inline comment
	var commentToken string
	for i, token := range tokens {
		if strings.HasPrefix(token, "#") {
			commentToken = strings.TrimSpace(token[1:])
			tokens = tokens[:i] // Remove comment and everything after
			break
		}
	}
	rule.Comment = commentToken

	if len(tokens) == 0 {
		return nil, "", fmt.Errorf("empty rule at line %d", lineNum)
	}

	var tokenIdx int

	// Check for directive (e.g., @include)
	if strings.HasPrefix(tokens[0], "@") {
		return p.parseDirective(tokens, &rule, lineNum)
	}

	// Parse service (only for /etc/pam.conf format)
	if !isPamD {
		if len(tokens) <= tokenIdx {
			return nil, "", fmt.Errorf("missing service field at line %d", lineNum)
		}
		rule.Service = tokens[tokenIdx]
		tokenIdx++
	}

	// Parse type
	if len(tokens) <= tokenIdx {
		return nil, "", fmt.Errorf("missing type field at line %d", lineNum)
	}
	if !IsValidModuleType(tokens[tokenIdx]) {
		return nil, "", fmt.Errorf("invalid module type '%s' at line %d", tokens[tokenIdx], lineNum)
	}
	// Store the original type (including negative prefix if present)
	rule.Type = ModuleType(strings.ToLower(tokens[tokenIdx]))
	tokenIdx++

	// Parse control
	if len(tokens) <= tokenIdx {
		return nil, "", fmt.Errorf("missing control field at line %d", lineNum)
	}

	control, err := p.parseControl(tokens[tokenIdx])
	if err != nil {
		return nil, "", fmt.Errorf("error parsing control at line %d: %w", lineNum, err)
	}
	rule.Control = control
	tokenIdx++

	// Parse module path
	if len(tokens) <= tokenIdx {
		return nil, "", fmt.Errorf("missing module path at line %d", lineNum)
	}
	rule.ModulePath = tokens[tokenIdx]
	tokenIdx++

	// Parse arguments (rest of the tokens)
	if tokenIdx < len(tokens) {
		argStr := strings.Join(tokens[tokenIdx:], " ")
		rule.Arguments = p.parseArguments(argStr)
	}

	return &rule, "", nil
}

// handleContinuation processes line continuation logic
func (p *Parser) handleContinuation(currentRule *Rule, currentLine *strings.Builder, line string, isPamD bool, serviceName string, config *Config) error {
	currentLine.WriteString(" ")
	currentLine.WriteString(strings.TrimSpace(line))

	// Check if this line continues
	if !strings.HasSuffix(strings.TrimSpace(line), "\\") {
		// End of continuation, parse the complete line
		completeLine := currentLine.String()
		rule, comment, err := p.parseLine(completeLine, currentRule.LineNumber, isPamD, serviceName)
		if err != nil {
			return err
		}

		if rule != nil {
			config.Rules = append(config.Rules, *rule)
		} else if comment != "" {
			config.Comments = append(config.Comments, comment)
		}

		currentRule = nil
		currentLine.Reset()
	}
	return nil
}

// Parse parses a PAM configuration from a reader
func (p *Parser) Parse(reader io.Reader, isPamD bool) (*Config, error) {
	return p.ParseWithService(reader, isPamD, "")
}

// ParseWithService parses a PAM configuration from a reader with an optional service name
// For pam.d format files, if serviceName is provided, it will be set on all rules
func (p *Parser) ParseWithService(reader io.Reader, isPamD bool, serviceName string) (*Config, error) {
	config := &Config{
		IsPamD: isPamD,
	}

	scanner := bufio.NewScanner(reader)
	lineNum := 0
	var currentRule *Rule
	var currentLine strings.Builder

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Handle continuation from previous line
		if currentRule != nil {
			err := p.handleContinuation(currentRule, &currentLine, line, isPamD, serviceName, config)
			if err != nil {
				return nil, err
			}
			continue
		}

		rule, comment, err := p.parseLine(line, lineNum, isPamD, serviceName)
		if err != nil {
			return nil, err
		}

		if rule != nil {
			if rule.Continuation {
				// Start of a continuation
				currentRule = rule
				currentLine.WriteString(line[:len(line)-1]) // Remove the \ at the end
			} else {
				config.Rules = append(config.Rules, *rule)
			}
		} else if comment != "" {
			config.Comments = append(config.Comments, comment)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %w", err)
	}

	return config, nil
}
