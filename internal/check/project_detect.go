package check

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ammaarrehman/hammerhead/internal/finding"
)

const (
	projectDetectCheckID      = "PROJ-002"
	projectDetectCheckName    = "project-runtime-detection"
	projectDetectCheckVersion = "0.1.0"
)

type ecosystemSignature struct {
	ecosystem string
	match     func(path, base string) bool
}

var ecosystemSignatures = []ecosystemSignature{
	{
		ecosystem: "Go",
		match: func(_, base string) bool {
			return base == "go.mod"
		},
	},
	{
		ecosystem: "Node.js / JavaScript / TypeScript",
		match: func(_, base string) bool {
			return base == "package.json"
		},
	},
	{
		ecosystem: "Python",
		match: func(_, base string) bool {
			return base == "pyproject.toml" || base == "requirements.txt" || base == "Pipfile" || base == "setup.py"
		},
	},
	{
		ecosystem: "Rust",
		match: func(_, base string) bool {
			return base == "Cargo.toml"
		},
	},
	{
		ecosystem: "Java / JVM",
		match: func(_, base string) bool {
			return base == "pom.xml" || base == "build.gradle" || base == "build.gradle.kts"
		},
	},
	{
		ecosystem: "Ruby",
		match: func(_, base string) bool {
			return base == "Gemfile"
		},
	},
	{
		ecosystem: "PHP",
		match: func(_, base string) bool {
			return base == "composer.json"
		},
	},
	{
		ecosystem: "Docker / Container",
		match: func(_, base string) bool {
			return base == "Dockerfile" || base == "docker-compose.yml" || base == "compose.yaml"
		},
	},
	{
		ecosystem: "Terraform / IaC",
		match: func(_, base string) bool {
			return strings.HasSuffix(base, ".tf")
		},
	},
}

// ProjectDetectCheck inspects repository files for language runtimes, package managers,
// and infrastructure manifests.
//
// These findings are strictly informational (SeverityInfo, CategoryProject) and provide
// context for developer tooling and subsequent dependency/IaC scanners.
type ProjectDetectCheck struct{}

func (c *ProjectDetectCheck) Meta() Meta {
	return Meta{
		ID:          projectDetectCheckID,
		Name:        projectDetectCheckName,
		Category:    finding.CategoryProject,
		Description: "Identifies project ecosystems, language runtimes, and manifest files to provide context",
		Version:     projectDetectCheckVersion,
	}
}

func (c *ProjectDetectCheck) Run(ctx context.Context, sc *ScanContext) error {
	detected := make(map[string]string) // ecosystem -> manifest path

	for _, file := range sc.Files {
		if err := ctx.Err(); err != nil {
			return err
		}

		if file.IsDir {
			continue
		}

		if sc.Coverage != nil {
			sc.Coverage.EligibleFiles++
			sc.Coverage.InspectedFiles++
		}

		base := filepath.Base(file.Path)
		for _, sig := range ecosystemSignatures {
			if _, alreadyFound := detected[sig.ecosystem]; alreadyFound {
				continue
			}
			if sig.match(file.Path, base) {
				detected[sig.ecosystem] = file.Path
			}
		}
	}

	if len(detected) == 0 {
		return nil
	}

	for eco, manifestPath := range detected {
		title := fmt.Sprintf("Project runtime: %s", eco)
		desc := fmt.Sprintf("Identified %s project ecosystem from manifest file '%s'.", eco, manifestPath)

		err := sc.Emit(finding.Finding{
			ID:          finding.GenerateID(projectDetectCheckID, eco),
			RuleID:      projectDetectCheckID,
			Class:       finding.ClassInfo,
			Category:    finding.CategoryProject,
			Severity:    finding.SeverityInfo,
			Confidence:  finding.ConfidenceHigh,
			Title:       title,
			Description: desc,
			Remediation: "Informational: project context identified for scanner workflows.",
			Path:        manifestPath,
			Evidence:    filepath.Base(manifestPath),
			Source:      "hammerhead",
			CheckVer:    projectDetectCheckVersion,
		})
		if err != nil {
			return err
		}
	}

	return nil
}
