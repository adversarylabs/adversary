package cmd

import (
	"context"
	"errors"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
)

// ExitCode maps stable error classes at the single process edge. Commands and
// libraries retain typed errors and never terminate the process themselves.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if application.IsKind(err, "network") || application.IsKind(err, "auth") {
		return 4
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 3
	}
	var findings *internaladversary.FindingsError
	if errors.As(err, &findings) {
		return 1
	}
	var processErr *internaladversary.ChildExitError
	if errors.As(err, &processErr) {
		return 3
	}
	var protocolErr *internaladversary.ProtocolError
	if errors.As(err, &protocolErr) {
		return 3
	}
	var executionErr *internaladversary.ExecutionError
	if errors.As(err, &executionErr) {
		return 3
	}
	var autoExecutionErr *internaladversary.AutoExecutionError
	if errors.As(err, &autoExecutionErr) {
		return 3
	}
	if application.IsKind(err, "usage") || application.IsKind(err, "configuration") || application.IsKind(err, "confirmation") {
		return 2
	}
	return 2
}
