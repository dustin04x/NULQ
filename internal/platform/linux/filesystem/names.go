//go:build linux

package filesystem

import (
	"os/user"
	"strconv"
	"sync"
)

// nameCache resolves numeric IDs to names once per scan. Name service lookups
// can be slow or fail in restricted environments, so failures fall back to a
// stable numeric representation instead of dropping the observation.
type nameCache struct {
	mu     sync.RWMutex
	users  map[uint32]string
	groups map[uint32]string
}

func newNameCache() *nameCache {
	return &nameCache{
		users:  make(map[uint32]string),
		groups: make(map[uint32]string),
	}
}

func (c *nameCache) userName(uid uint32) string {
	c.mu.RLock()
	name, ok := c.users[uid]
	c.mu.RUnlock()
	if ok {
		return name
	}

	resolved := "uid-" + strconv.FormatUint(uint64(uid), 10)
	if entry, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil && entry.Username != "" {
		resolved = entry.Username
	}

	c.mu.Lock()
	c.users[uid] = resolved
	c.mu.Unlock()
	return resolved
}

func (c *nameCache) groupName(gid uint32) string {
	c.mu.RLock()
	name, ok := c.groups[gid]
	c.mu.RUnlock()
	if ok {
		return name
	}

	resolved := "gid-" + strconv.FormatUint(uint64(gid), 10)
	if entry, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil && entry.Name != "" {
		resolved = entry.Name
	}

	c.mu.Lock()
	c.groups[gid] = resolved
	c.mu.Unlock()
	return resolved
}
