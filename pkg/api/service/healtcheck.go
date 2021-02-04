/*
Copyright 2021 Adevinta
*/

package service

import (
	"context"
)

type persistenceHealthChecker interface {
	Ping() error
}

// HealthcheckService provides functionality to check the health of the service.
type HealthcheckService struct {
	DB persistenceHealthChecker
}

// Healthcheck checks the health of the service.
func (s HealthcheckService) Healthcheck(ctx context.Context) error {
	return s.DB.Ping()
}
