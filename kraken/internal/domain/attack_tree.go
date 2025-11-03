package domain

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

type NodeType string

const (
	LEAF NodeType = "LEAF"
	AND  NodeType = "AND"
	OR   NodeType = "OR"
)

type SuccessMode string

const (
	SuccessModeAny       SuccessMode = "any"
	SuccessModeAll       SuccessMode = "all"
	SuccessModeThreshold SuccessMode = "threshold"
)

type AttackNode struct {
	Name     string        `yaml:"name"`
	Type     NodeType      `yaml:"type"`
	Children []*AttackNode `yaml:"children,omitempty"`
	Success  bool

	// NOTE: Only used on LEAF nodes
	FindingIDs       []string    `yaml:"finding_ids"`
	FindingMode      SuccessMode `yaml:"finding_mode"`
	FindingThreshold int         `yaml:"finding_threshold,omitempty"`
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
	switch t.FindingMode {
	case SuccessModeAny:
		{
			for _, fid := range t.FindingIDs {
				for _, finding := range findings {
					if fid == finding.ID && finding.Success {
						t.Success = true
						return true
					}
				}
			}
			return false
		}
	case SuccessModeAll:
		{
			for _, fid := range t.FindingIDs {
				for _, finding := range findings {
					if fid == finding.ID && !finding.Success {
						return false
					}
				}
			}
			t.Success = true
			return true
		}
	case SuccessModeThreshold:
		{
			count := 0
			for _, pid := range t.FindingIDs {
				for _, finding := range findings {
					if pid == finding.ID && finding.Success {
						count += 1
						if count >= t.FindingThreshold {
							t.Success = true
							return true
						}
					}
				}
			}
			return false
		}
	default:
		log.Errorf("Invalid plugin mode in attack tree's settings (available types are: any, all, threshold): %s\n", pluginModeToString(t.FindingMode))
		return false
	}
}

func (t *AttackNode) PrintTree(prefix string) {
	status := ""
	if t.Type == LEAF {
		status = fmt.Sprintf(" Success: %v", t.Success)
	}
	fmt.Printf("%s - %s [%s]%s\n", prefix, t.Name, nodeTypeToString(t.Type), status)

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

func pluginModeToString(m SuccessMode) string {
	switch m {
	case SuccessModeAll:
		return "all"
	case SuccessModeThreshold:
		return "threshold"
	case SuccessModeAny:
		return "any"
	default:
		return string(m)
	}
}
