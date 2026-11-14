// Package golden compares rendered output with files under testdata/ so a
// change to a renderer shows up in review as a diff of what it produces.
//
// Run the tests with -update to rewrite the files:
//
//	go test ./internal/... -update
package golden

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files instead of comparing")

// Assert compares got with testdata/<name>. With -update it writes the file.
func Assert(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden file missing: %v (run the test with -update to create it)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from the rendered output (run with -update after reviewing):\n%s", path, diff(string(want), string(got)))
	}
}

// diff shows the first differing line with a little context; enough to see
// what moved without pulling in a diff library.
func diff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return "line " + itoa(i+1) + ":\n- " + a + "\n+ " + b
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
