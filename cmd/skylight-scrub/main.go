// Command skylight-scrub turns one skylight-probe capture run into committed
// test fixtures (internal/skylight/testdata). All documents share one
// Scrubber, so ids still cross-reference. Nothing is written unless every
// document passes the leak check. Review the diff before committing anyway.
//
//	go run ./cmd/skylight-scrub captures/<run>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/logich/skylight-mcp-aws/internal/scrub"
)

var (
	shape = regexp.MustCompile(`[A-Za-z]`)
	digit = regexp.MustCompile(`[0-9]`)
)

var docs = []string{"frames.json", "categories.json", "events.json", "events-no-include.json"}

func main() {
	if len(os.Args) != 2 {
		fail(fmt.Errorf("usage: skylight-scrub captures/<run>"))
	}
	s, err := scrub.New()
	if err != nil {
		fail(err)
	}
	out := map[string][]byte{}
	for _, name := range docs {
		in, err := os.ReadFile(filepath.Join(os.Args[1], name))
		if err != nil {
			fail(err)
		}
		b, err := s.Document(in)
		if err != nil {
			fail(fmt.Errorf("%s: %w", name, err))
		}
		out[name] = b
	}
	// Check after all documents, so a value first seen in a later document is
	// also caught in earlier outputs.
	for _, name := range docs {
		if leaks := s.Check(out[name]); len(leaks) > 0 {
			for _, l := range leaks {
				// Shape only (letters a, digits 9), never the value.
				fmt.Fprintf(os.Stderr, "  leak in %s: shape %q\n", name, shape.ReplaceAllString(digit.ReplaceAllString(l, "9"), "a"))
			}
			fail(fmt.Errorf("%s: %d original values survived scrubbing; nothing written", name, len(leaks)))
		}
	}
	dir := filepath.Join("internal", "skylight", "testdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail(err)
	}
	for _, name := range docs {
		if err := os.WriteFile(filepath.Join(dir, name), append(out[name], '\n'), 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(dir, name), len(out[name]))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "skylight-scrub:", err)
	os.Exit(1)
}
