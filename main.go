package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	format := flag.String("format", "text", "Output format: text, json")
	exitCode := flag.Int("exit-code", 1, "Exit code when leaks found")
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	var all []Finding
	for _, p := range paths {
		err := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".py") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			all = append(all, Scan(path, string(data))...)
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error walking %s: %v\n", p, err)
		}
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if len(all) == 0 {
			all = []Finding{}
		}
		enc.Encode(all)
	default:
		for _, f := range all {
			fmt.Printf("\xf0\x9f\x94\xb4 %s:%d [%s] %s\n   %s \xe2\x86\x92 %s (var: %s)\n\n",
				f.File, f.Line, f.Severity, f.Message, f.Source, f.Sink, f.Variable)
		}
	}

	if len(all) > 0 {
		fmt.Fprintf(os.Stderr, "\xe2\x9d\x8c %d sensitive data leak path(s) found\n", len(all))
		os.Exit(*exitCode)
	}
	fmt.Fprintln(os.Stderr, "\xe2\x9c\x85 No sensitive data leaks detected")
}
