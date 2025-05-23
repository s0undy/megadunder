package handlers

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/s0undy/megadunder/internal/api/models"
)

// IPHandler defines the interface for IP version specific handlers
type IPHandler interface {
	ExecuteCommand(command string, address string) *models.IPToolsResponse
	ValidateAddress(address string) bool
}

// allowedCommands defines the commands that can be executed
var allowedCommands = map[string]bool{
	"curl":       true,
	"ping":       true,
	"traceroute": true,
	"telnet":     true,
}

// executeCommand is a helper function to run system commands
func executeCommand(cmd *exec.Cmd) *models.IPToolsResponse {
	var ctx context.Context
	var cancel context.CancelFunc

	// Add timeout for curl and telnet commands
	if len(cmd.Args) > 0 && (cmd.Args[0] == "curl" || cmd.Args[0] == "telnet") {
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	}

	output, err := cmd.CombinedOutput()
	response := &models.IPToolsResponse{
		Output: string(output),
	}

	if err != nil {
		// Check if this is a timeout error (either from context or from curl's --max-time)
		if ctx != nil && ctx.Err() == context.DeadlineExceeded || err.Error() == "signal: killed" ||
			(len(output) > 0 && (strings.Contains(string(output), "Operation timed out") ||
				strings.Contains(string(output), "Timeout was reached"))) {
			response.Error = "Command timed out after 10 seconds"
		} else {
			response.Error = err.Error()
		}
	}

	return response
}

// validateCommand checks if the command is allowed
func validateCommand(command string) bool {
	return allowedCommands[command]
}
