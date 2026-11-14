//go:build !windows

package main

import "errors"

func serviceCommand(args []string) error {
	return errors.New("the agent service is Windows only; run the agent in the foreground on this OS")
}

func runHelper() error { return errors.New("the service helper is Windows only") }

func runAsService() (bool, error) { return false, nil }
