package sandbox

import "testing"

func TestExposesHome(t *testing.T) {
	home := "/home/alice"
	cases := map[string]bool{
		"/home/alice":            true,
		"/home":                  true,
		"/home/bob":              true,
		"/root":                  true,
		"/":                      true,
		"/home/alice/projects":   false,
		"/home/alice/projects/x": false,
		"/opt/servers":           false,
	}
	for dir, want := range cases {
		if got := exposesHome(dir, home); got != want {
			t.Errorf("exposesHome(%q) = %v, want %v", dir, got, want)
		}
	}
}
