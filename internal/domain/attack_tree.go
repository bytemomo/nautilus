package domain

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

type NodeType uint8

const (
	LEAF NodeType = iota
	AND
	OR
)

type PluginMode string

const (
	PluginModeAny       PluginMode = "any"
	PluginModeAll       PluginMode = "all"
	PluginModeThreshold PluginMode = "threshold"
)

type AttackNode struct {
	Name     string        `yaml:"name"`
	Type     NodeType      `yaml:"type"`
	Children []*AttackNode `yaml:"children,omitempty"`
	Success  bool

	// NOTE: Only used on LEAF nodes
	PluginIDs       []string   `yaml:"plugin_ids"`
	PluginMode      PluginMode `yaml:"plugin_mode"`
	PluginThreshold int        `yaml:"plugin_threshold,omitempty"`
}

func (t *AttackNode) Evaluate(findings []Finding) bool {
	switch t.Type {
	case LEAF:
		return t.EvaluateLeaf(findings)
	case AND:
		{
			for _, child := range t.Children {
				if !child.Evaluate(findings) {
					return false
				}
			}
			t.Success = true
			return true
		}
	case OR:
		{
			for _, child := range t.Children {
				if child.Evaluate(findings) {
					t.Success = true
					return true
				}
			}
			return false
		}
	default:
		log.Errorf("Invalid attack tree's node type (available types are: LEAF, OR, AND): %s\n", nodeTypeToString(t.Type))
		return false
	}
}

func (t *AttackNode) EvaluateLeaf(findings []Finding) bool {
	switch t.PluginMode {
	case PluginModeAny:
		{

			for _, pid := range t.PluginIDs {
				for _, finding := range findings {
					if pid == finding.PluginID && finding.Success {
						t.Success = true
						return true
					}
				}
			}
			return false
		}
	case PluginModeAll:
		{
			for _, pid := range t.PluginIDs {
				for _, finding := range findings {
					if pid == finding.PluginID && !finding.Success {
						return false
					}
				}
			}
			t.Success = true
			return true
		}
	case PluginModeThreshold:
		{
			count := 0
			for _, pid := range t.PluginIDs {
				for _, finding := range findings {
					if pid == finding.PluginID && !finding.Success {
						count += 1
						if count >= t.PluginThreshold {
							t.Success = true
							return true
						}
					}
				}
			}
			return false
		}
	default:
		log.Errorf("Invalid plugin mode in attack tree's settings (available types are: any, all, threshold): %s\n", pluginModeToString(t.PluginMode))
		return false
	}
}

func (t *AttackNode) PrintTree(prefix string) {
	status := ""
	if t.Type == LEAF {
		status = fmt.Sprintf(" Success: %v", t.Success)
	}
	fmt.Printf("%s- %s [%s]%s\n", prefix, t.Name, nodeTypeToString(t.Type), status)

	for _, child := range t.Children {
		child.PrintTree(prefix + "  ")
	}
}

func nodeTypeToString(t NodeType) string {
	switch t {
	case LEAF:
		return "LEAF"
	case AND:
		return "AND"
	case OR:
		return "OR"
	default:
		return string(t)
	}
}

func pluginModeToString(m PluginMode) string {
	switch m {
	case PluginModeAll:
		return "all"
	case PluginModeThreshold:
		return "threshold"
	case PluginModeAny:
		return "any"
	default:
		return string(m)
	}
}
