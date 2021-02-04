/*
Copyright 2021 Adevinta
*/

package scans

type ChecksRunnerForTask interface {
	CreateIncompleteScansChecks() error
}

// ChecksRunnerTask implements a periodic check creator than can
// be run by the Scheduler.
type ChecksRunnerTask struct {
	ChecksRunnerForTask
}

func (c *ChecksRunnerTask) Name() string {
	return "ChecksCreatorTask"
}

func (c *ChecksRunnerTask) Type() string {
	return "CheckCreator"
}

func (c *ChecksRunnerTask) Execute() error {
	err := c.CreateIncompleteScansChecks()
	if err != nil {
		return err
	}
	return nil
}
