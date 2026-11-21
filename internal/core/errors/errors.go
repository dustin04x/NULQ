// Package nulqerr defines the typed error model used across NULQ.
//
// Errors are classified so that collectors, rules and the CLI can make
// honest distinctions between "we were not allowed to look", "the resource
// does not exist", "this kernel does not support the operation" and genuine
// internal failures. Classification is never used to hide an error: the
// original error is always preserved with errors.Unwrap.
package nulqerr

import (
	"context"
	stderrors "errors"
	"fmt"
	"io/fs"
	"os"
)

// Class is the category of a failure.
type Class string

const (
	ClassPermissionDenied  Class = "permission_denied"
	ClassNotFound          Class = "not_found"
	ClassUnavailable       Class = "unavailable"
	ClassUnsupported       Class = "unsupported"
	ClassMalformedInput    Class = "malformed_input"
	ClassTimeout           Class = "timeout"
	ClassCanceled          Class = "canceled"
	ClassResourceExhausted Class = "resource_exhausted"
	ClassInternal          Class = "internal"
)

// Valid reports whether c is a known class.
func (c Class) Valid() bool {
	switch c {
	case ClassPermissionDenied, ClassNotFound, ClassUnavailable, ClassUnsupported,
		ClassMalformedInput, ClassTimeout, ClassCanceled, ClassResourceExhausted, ClassInternal:
		return true
	}
	return false
}

// Error is a classified tool error.
type Error struct {
	Class    Class
	Op       string
	Resource string
	Err      error
}

// Error implements the error interface.
func (e *Error) Error() string {
	switch {
	case e.Resource != "" && e.Err != nil:
		return fmt.Sprintf("%s %s: %s: %v", e.Op, e.Resource, e.Class, e.Err)
	case e.Resource != "":
		return fmt.Sprintf("%s %s: %s", e.Op, e.Resource, e.Class)
	case e.Err != nil:
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Class, e.Err)
	default:
		return fmt.Sprintf("%s: %s", e.Op, e.Class)
	}
}

// Unwrap exposes the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// New builds a classified error.
func New(class Class, op, resource string, err error) *Error {
	return &Error{Class: class, Op: op, Resource: resource, Err: err}
}

// Classify infers a class from a raw error and wraps it.
func Classify(op, resource string, err error) *Error {
	return New(ClassOf(err), op, resource, err)
}

// ClassOf reports the class of err, inferring one when err is not already
// classified.
func ClassOf(err error) Class {
	if err == nil {
		return ""
	}
	var classified *Error
	if stderrors.As(err, &classified) {
		return classified.Class
	}
	switch {
	case stderrors.Is(err, context.DeadlineExceeded):
		return ClassTimeout
	case stderrors.Is(err, context.Canceled):
		return ClassCanceled
	case stderrors.Is(err, fs.ErrPermission), stderrors.Is(err, os.ErrPermission):
		return ClassPermissionDenied
	case stderrors.Is(err, fs.ErrNotExist), stderrors.Is(err, os.ErrNotExist):
		return ClassNotFound
	}
	return ClassInternal
}

// IsClass reports whether err carries the given class.
func IsClass(err error, class Class) bool {
	return ClassOf(err) == class
}

// Permission builds a permission-denied error.
func Permission(op, resource string, err error) *Error {
	return New(ClassPermissionDenied, op, resource, err)
}

// Unavailable builds an unavailable-resource error.
func Unavailable(op, resource string, err error) *Error {
	return New(ClassUnavailable, op, resource, err)
}

// Unsupported builds an unsupported-operation error.
func Unsupported(op, resource string, err error) *Error {
	return New(ClassUnsupported, op, resource, err)
}

// Malformed builds a malformed-input error.
func Malformed(op, resource string, err error) *Error {
	return New(ClassMalformedInput, op, resource, err)
}

// Timeout builds a timeout error.
func Timeout(op, resource string) *Error {
	return New(ClassTimeout, op, resource, context.DeadlineExceeded)
}
