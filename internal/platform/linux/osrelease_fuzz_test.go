package linux

import "testing"

func FuzzParseOSRelease(f *testing.F) {
	f.Add([]byte("ID=ubuntu\nVERSION_ID=\"22.04\"\nID_LIKE=debian\n"))
	f.Add([]byte(""))
	f.Add([]byte("ID=alpine\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseOSReleaseBytes(data)
		if err != nil {
			return
		}
		_ = r.DistributionFamily()
	})
}
