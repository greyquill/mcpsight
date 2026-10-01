package injection

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"

	"github.com/greyquill/mcpsight/internal/analyze"
	"gopkg.in/yaml.v3"
)

//go:embed rules/patterns.yaml
var defaultRules []byte

// Rule is one regex-based injection pattern loaded from YAML.
type Rule struct {
	ID          string   `yaml:"id"`
	Severity    string   `yaml:"severity"`
	Title       string   `yaml:"title"`
	Detail      string   `yaml:"detail"`
	Remediation string   `yaml:"remediation"`
	Any         []string `yaml:"any"`

	compiled []*regexp.Regexp
}

// RuleSet is a versioned collection of rules.
type RuleSet struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// DefaultRuleSet returns the embedded, compiled rule set.
func DefaultRuleSet() (*RuleSet, error) { return parseRules(defaultRules) }

// LoadRuleSet loads and compiles a rule set from a YAML file, for --rules.
func LoadRuleSet(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRules(data)
}

func parseRules(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parsing injection rules: %w", err)
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.Severity == "" {
			return nil, fmt.Errorf("rule %q: missing severity", r.ID)
		}
		for _, pat := range r.Any {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad pattern %q: %w", r.ID, pat, err)
			}
			r.compiled = append(r.compiled, re)
		}
	}
	return &rs, nil
}

// match reports whether any of the rule's patterns match text.
func (r *Rule) match(text string) bool {
	for _, re := range r.compiled {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func severity(s string) analyze.Severity {
	switch s {
	case "critical":
		return analyze.Critical
	case "high":
		return analyze.High
	case "medium":
		return analyze.Medium
	case "low":
		return analyze.Low
	default:
		return analyze.Info
	}
}
