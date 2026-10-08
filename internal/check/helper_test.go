package check_test

import (
	"context"

	"github.com/ammaarrehman/hammerhead/internal/check"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/scanstate"
)

func runCheckForTest(c check.Check, sc *check.ScanContext) ([]finding.Finding, error) {
	limits := scanstate.ProductionLimits()
	collector := scanstate.NewCollector(limits)

	sc.Emit = collector.Emit
	err := c.Run(context.Background(), sc)
	if err != nil {
		// If the error is budget exhausted, that is considered a successful early stop,
		// but the check returns it. For testing rules we usually just want findings.
		// However, some tests explicitly want the error.
		return collector.Findings(), err
	}

	return collector.Findings(), nil
}

func runCheckForTestWithLimit(c check.Check, sc *check.ScanContext, limit int) ([]finding.Finding, error) {
	limits := scanstate.ProductionLimits()
	limits.MaxFindings = limit
	collector := scanstate.NewCollector(limits)

	sc.Emit = collector.Emit

	err := c.Run(context.Background(), sc)
	return collector.Findings(), err
}
