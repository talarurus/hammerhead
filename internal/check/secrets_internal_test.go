package check

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSecretPatternCheck_MatchFloodBounded(t *testing.T) {
	// Use 1000 valid generated keys
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n")
	}
	content := []byte(sb.String())

	ctx := context.Background()
	visits := 0
	errBudgetExhausted := errors.New("simulated budget exhaustion")

	err := iterateAWSAccessKeys(ctx, content, func(m awsMatch) error {
		visits++
		// Simulate stopping exactly when the 4th key is visited
		if visits >= 4 {
			return errBudgetExhausted
		}
		return nil
	})

	if err != errBudgetExhausted {
		t.Fatalf("Expected errBudgetExhausted, got %v", err)
	}

	// Test MUST assert that exactly 4 matches are visited by iterateAWSAccessKeys.
	if visits != 4 {
		t.Errorf("Expected exactly 4 visits, got %d", visits)
	}
}
