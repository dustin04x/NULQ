package models

import (
	"fmt"
	"io/fs"
)

// ModeOctal renders the permission bits of mode as four octal digits,
// including setuid, setgid and sticky bits (for example "4755").
func ModeOctal(mode fs.FileMode) string {
	bits := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return fmt.Sprintf("%04o", bits)
}

// ModeSymbolic renders permission bits in ls(1) form, for example "rwsr-xr-x".
func ModeSymbolic(mode fs.FileMode) string {
	perm := mode.Perm()
	out := make([]byte, 9)
	const rwx = "rwxrwxrwx"
	for i := 0; i < 9; i++ {
		if perm&(1<<uint(8-i)) != 0 {
			out[i] = rwx[i]
		} else {
			out[i] = '-'
		}
	}
	if mode&fs.ModeSetuid != 0 {
		if out[2] == 'x' {
			out[2] = 's'
		} else {
			out[2] = 'S'
		}
	}
	if mode&fs.ModeSetgid != 0 {
		if out[5] == 'x' {
			out[5] = 's'
		} else {
			out[5] = 'S'
		}
	}
	if mode&fs.ModeSticky != 0 {
		if out[8] == 'x' {
			out[8] = 't'
		} else {
			out[8] = 'T'
		}
	}
	return string(out)
}
