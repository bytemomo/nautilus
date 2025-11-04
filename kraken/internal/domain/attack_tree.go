package domain

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// NodeType is the type of a node in an attack tree.
type NodeType string

const (
	// LEAF is a leaf node in an attack tree.
	LEAF NodeType = "LEAF"
	// AND is an AND node in an attack tree.
	AND NodeType = "AND"
	// OR is an OR node in an attack tree.
	OR NodeType = "OR"
)

// SuccessMode is the mode for determining success of a leaf node.
type SuccessMode string

const (
	// SuccessModeAny means any finding is enough for success.
	SuccessModeAny SuccessMode = "any"
	// SuccessModeAll means all findings must be successful.
	SuccessModeAll SuccessMode = "all"
	// SuccessModeThreshold means a certain number of findings must be successful.
	SuccessModeThreshold SuccessMode = "threshold"
)

// AttackNode is a node in an attack tree.
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

// Evaluate evaluates the attack tree against a set of findings.
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

// EvaluateLeaf evaluates a leaf node against a set of findings.
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
		log.Errorf("Invalid module mode in attack tree's settings (available types are: any, all, threshold): %s\n", moduleModeToString(t.FindingMode))
		return false
	}
}

// RenderTree renders the attack tree as a Mermaid graph.
func (t *AttackNode) RenderTree() string {
	var sb strings.Builder
	sb.WriteString("graph TD\n")

	var counter int
	var renderNode func(node *AttackNode, parentID string)

	renderNode = func(node *AttackNode, parentID string) {
		counter++
		nodeID := fmt.Sprintf("N%d", counter)

		var label string
		switch node.Type {
		case AND:
			label = fmt.Sprintf("%s{AND}", node.Name)
		case OR:
			label = fmt.Sprintf("%s{OR}", node.Name)
		case LEAF:
			label = fmt.Sprintf("%s[%s]", node.Name, "LEAF")
		default:
			label = node.Name
		}

		sb.WriteString(fmt.Sprintf("    %s[%q]\n", nodeID, label))
		if parentID != "" {
			sb.WriteString(fmt.Sprintf("    %s --- %s\n", parentID, nodeID))
		}
		if node.Success {
			sb.WriteString(fmt.Sprintf("    class %s success;\n", nodeID))
		}
		for _, child := range node.Children {
			renderNode(child, nodeID)
		}
	}

	renderNode(t, "")

	// Define Mermaid classes
	sb.WriteString("\n    classDef success fill:#ffcccc,stroke:#ff0000,stroke-width:2px;\n")

	return sb.String()
}

// PrintTree prints the attack tree to the console.
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

func moduleModeToString(m SuccessMode) string {
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
