package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Kind identifies the type of an observation. Kinds are a closed vocabulary:
// detection rules depend on stable, documented kinds, never on collector
// implementation details.
type Kind string

const (
	KindSystemInfo         Kind = "system.info"
	KindSecurityControl    Kind = "system.security_control"
	KindSysctl             Kind = "system.sysctl"
	KindExecutionContext   Kind = "identity.execution_context"
	KindGroupMembership    Kind = "identity.group_membership"
	KindFile               Kind = "filesystem.file"
	KindDirectory          Kind = "filesystem.directory"
	KindPathEntry          Kind = "filesystem.path_entry"
	KindMount              Kind = "filesystem.mount"
	KindFilesystemScan     Kind = "filesystem.scan"
	KindProcess            Kind = "process.info"
	KindSystemdUnit        Kind = "system.systemd_unit"
	KindFileCapability     Kind = "filesystem.capability"
	KindSudoRule           Kind = "identity.sudo_rule"
	KindCronJob            Kind = "identity.cron_job"
	KindContainerIndicator Kind = "system.container_indicator"
	KindKernelMitigation   Kind = "system.kernel_mitigation"
	KindSecurityPolicy     Kind = "system.security_policy"
	KindUserAccount        Kind = "identity.user_account"
	KindSSHDConfig         Kind = "system.sshd_config"
	KindSSHAuthorizedKeys  Kind = "identity.ssh_authorized_keys"
)

// AllKinds returns every observation kind in a stable order.
func AllKinds() []Kind {
	return []Kind{
		KindSystemInfo,
		KindSecurityControl,
		KindSysctl,
		KindExecutionContext,
		KindGroupMembership,
		KindFile,
		KindDirectory,
		KindPathEntry,
		KindMount,
		KindFilesystemScan,
		KindProcess,
		KindSystemdUnit,
		KindFileCapability,
		KindSudoRule,
		KindCronJob,
		KindContainerIndicator,
		KindKernelMitigation,
		KindSecurityPolicy,
		KindUserAccount,
		KindSSHDConfig,
		KindSSHAuthorizedKeys,
	}
}

// Status describes how completely a collector was able to observe a resource.
type Status string

const (
	// StatusComplete means the observation reflects the full resource state.
	StatusComplete Status = "complete"
	// StatusPartial means the observation is usable but incomplete, for
	// example because a scan budget was exhausted.
	StatusPartial Status = "partial"
	// StatusUnavailable means the resource could not be observed at all, for
	// example because access was denied or the kernel does not expose it.
	StatusUnavailable Status = "unavailable"
	// StatusError means collection failed unexpectedly.
	StatusError Status = "error"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	switch s {
	case StatusComplete, StatusPartial, StatusUnavailable, StatusError:
		return true
	}
	return false
}

// ObservationError records why an observation is unavailable or partial,
// using the same classes as the tool error model.
type ObservationError struct {
	Class    string `json:"class"`
	Message  string `json:"message"`
	Resource string `json:"resource,omitempty"`
}

// Observation is a normalized, reusable statement about the assessed system.
//
// Observations are the only input to detection rules. They are immutable once
// the collection phase ends, carry provenance (collector and timestamp) and
// never contain secrets: collectors must not record file contents, passwords,
// tokens or private keys.
type Observation struct {
	ID          string            `json:"id"`
	Kind        Kind              `json:"kind"`
	Resource    string            `json:"resource"`
	Collector   string            `json:"collector"`
	CollectedAt time.Time         `json:"collected_at"`
	Status      Status            `json:"status"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Note        string            `json:"note,omitempty"`
	Error       *ObservationError `json:"error,omitempty"`
}

// NewObservation builds a complete observation with a deterministic ID.
// The attribute map is copied so callers cannot mutate a published
// observation.
func NewObservation(kind Kind, resource, collector string, collectedAt time.Time, attributes map[string]string) Observation {
	return Observation{
		ID:          ObservationID(kind, resource),
		Kind:        kind,
		Resource:    resource,
		Collector:   collector,
		CollectedAt: collectedAt.UTC(),
		Status:      StatusComplete,
		Attributes:  cloneAttributes(attributes),
	}
}

// UnavailableObservation builds an observation for a resource that could not
// be read.
func UnavailableObservation(kind Kind, resource, collector string, collectedAt time.Time, cause ObservationError) Observation {
	obs := NewObservation(kind, resource, collector, collectedAt, nil)
	obs.Status = StatusUnavailable
	obs.Error = &cause
	return obs
}

// ObservationID derives a stable identifier from the kind and resource.
// It deliberately excludes timestamps and collector names so IDs are
// reproducible across scans of the same system state.
func ObservationID(kind Kind, resource string) string {
	return stableID("obs-"+kindSlug(kind), string(kind), resource)
}

// stableID returns prefix + "-" + the first six bytes of SHA-256 over parts.
func stableID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return prefix + "-" + hex.EncodeToString(h.Sum(nil)[:6])
}

func kindSlug(k Kind) string {
	return strings.ReplaceAll(string(k), ".", "-")
}

// Attr returns a single attribute value.
func (o Observation) Attr(key string) (string, bool) {
	value, ok := o.Attributes[key]
	return value, ok
}

// Bool returns a boolean attribute; absent or malformed values are false.
func (o Observation) Bool(key string) bool {
	value, ok := o.Attributes[key]
	if !ok {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

// Int returns an integer attribute.
func (o Observation) Int(key string) (int64, bool) {
	value, ok := o.Attributes[key]
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// Set writes an attribute. It is intended for collectors assembling an
// observation before publication.
func (o *Observation) Set(key, value string) {
	if o.Attributes == nil {
		o.Attributes = make(map[string]string)
	}
	o.Attributes[key] = value
}

// Clone returns a deep copy.
func (o Observation) Clone() Observation {
	clone := o
	clone.Attributes = cloneAttributes(o.Attributes)
	if o.Error != nil {
		errCopy := *o.Error
		clone.Error = &errCopy
	}
	return clone
}

func cloneAttributes(attributes map[string]string) map[string]string {
	if attributes == nil {
		return nil
	}
	clone := make(map[string]string, len(attributes))
	for k, v := range attributes {
		clone[k] = v
	}
	return clone
}

// String renders a compact human summary, useful in tests and debug logs.
func (o Observation) String() string {
	return fmt.Sprintf("%s[%s] %s (%s)", o.Kind, o.ID, o.Resource, o.Status)
}
