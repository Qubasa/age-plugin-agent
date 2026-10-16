package main

import (
	"fmt"
	"strings"
)

const (
	// MaxPluginNameLength is the maximum allowed length for plugin names
	MaxPluginNameLength = 64
	// PluginNamePattern is the regex pattern for valid plugin names
	PluginNamePattern = `^[a-zA-Z0-9-]+$`
	// maxHandshakeLine bounds the handshake line the server buffers
	maxHandshakeLine = 128
	stateMachineFlag = "--age-plugin"
)

// stateMachines are the age plugin state machines the agent forwards.
var stateMachines = map[string]bool{
	"identity-v1":  true,
	"recipient-v1": true,
}

func validateStateMachine(sm string) error {
	if !stateMachines[sm] {
		return fmt.Errorf("unsupported state machine %q", sm)
	}
	return nil
}

// parseStateMachine extracts the state machine age passes to a plugin as
// --age-plugin=<sm> (or --age-plugin <sm>).
func parseStateMachine(args []string) (string, error) {
	var sm string
	switch {
	case len(args) == 1 && strings.HasPrefix(args[0], stateMachineFlag+"="):
		sm = strings.TrimPrefix(args[0], stateMachineFlag+"=")
	case len(args) == 2 && args[0] == stateMachineFlag:
		sm = args[1]
	default:
		return "", fmt.Errorf("expected %s=<state-machine>, got %q", stateMachineFlag, args)
	}
	if err := validateStateMachine(sm); err != nil {
		return "", err
	}
	return sm, nil
}
