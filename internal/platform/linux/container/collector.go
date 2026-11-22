// Package container collects container and runtime indicators read-only.
package container

import (
	"context"
	"errors"
	"os"
	"time"

	nulqerr "github.com/dustin04x/nulq/internal/core/errors"
	"github.com/dustin04x/nulq/internal/core/models"
)

const collectorName = "linux.container"

// Collector discovers container/runtime indicators without touching the Docker socket or reading secrets.
type Collector struct {
	now func() time.Time
}

// NewCollector returns a container indicator collector.
func NewCollector() *Collector {
	return &Collector{now: func() time.Time { return time.Now().UTC() }}
}

// Name implements interfaces.Collector.
func (c *Collector) Name() string { return collectorName }

// Collect implements interfaces.Collector.
func (c *Collector) Collect(ctx context.Context) ([]models.Observation, error) {
	now := c.now()
	if err := ctx.Err(); err != nil {
		return nil, nulqerr.Classify("collect", collectorName, err)
	}

	var observations []models.Observation

	// Docker socket presence (we never connect to it)
	dockerSock := "/var/run/docker.sock"
	if _, err := os.Stat(dockerSock); err == nil {
		obs := models.NewObservation(models.KindContainerIndicator, dockerSock, collectorName, now, nil)
		obs.Set(models.AttrDockerSocket, "true")
		observations = append(observations, obs)
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		observations = append(observations, models.UnavailableObservation(
			models.KindContainerIndicator, dockerSock, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()}))
	}

	// Containerd socket presence
	containerdSock := "/run/containerd/containerd.sock"
	if _, err := os.Stat(containerdSock); err == nil {
		obs := models.NewObservation(models.KindContainerIndicator, containerdSock, collectorName, now, nil)
		obs.Set(models.AttrContainerMount, "true")
		observations = append(observations, obs)
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		observations = append(observations, models.UnavailableObservation(
			models.KindContainerIndicator, containerdSock, collectorName, now,
			models.ObservationError{Class: string(nulqerr.ClassOf(err)), Message: err.Error()}))
	}

	// /.dockerenv or /.containerize marker files
	for _, marker := range []string{"/.dockerenv", "/.containerize"} {
		if _, err := os.Stat(marker); err == nil {
			obs := models.NewObservation(models.KindContainerIndicator, marker, collectorName, now, nil)
			obs.Set(models.AttrContainerMount, "true")
			observations = append(observations, obs)
		}
	}

	return observations, nil
}
