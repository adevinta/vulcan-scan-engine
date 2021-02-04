/*
Copyright 2021 Adevinta
*/

package scans

// ChecksCreatorTask implements a periodic check creator than can
// be run by the Scheduler.
type ChecksCreatorTask struct {
	*ChecksCreator
}

func (c *ChecksCreatorTask) Name() string {
	return "ChecksCreatorTask"
}

func (c *ChecksCreatorTask) Type() string {
	return "CheckCreator"
}

func (c *ChecksCreatorTask) Execute() error {
	err := c.CreateIncompleteScansChecks()
	if err != nil {
		return err
	}
	return nil
}
