// Command gen writes the files derived from the model: the OpenAPI document
// and the UI form description. Run it through `go generate ./internal/model`.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/noahzmr/testudo/internal/model/schema"
)

func main() {
	// go generate runs in the directory of the file holding the directive,
	// which is internal/model.
	dir := "schema"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	for name, fn := range map[string]func() ([]byte, error){
		"openapi.json": schema.OpenAPI,
		"ui.json":      schema.UI,
	} {
		data, err := fn()
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen: %s: %v\n", name, err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "gen: %v\n", err)
			os.Exit(1)
		}
	}
}
