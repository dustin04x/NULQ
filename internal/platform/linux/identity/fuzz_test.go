package identity

import (
	"testing"
	"time"
)

func FuzzParsePasswdLine(f *testing.F) {
	f.Add("root:x:0:0:root:/root:/bin/bash\n")
	f.Add("bad::x:notanumber:0::\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = parsePasswdLine(data, time.Now().UTC(), "linux.identity")
	})
}

func FuzzParseGroupLine(f *testing.F) {
	f.Add("root:x:0:\n")
	f.Add("wheel:x:10:user1,user2\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = parseGroupLine(data, time.Now().UTC(), "linux.identity")
	})
}
