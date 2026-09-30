// Command renderpolicies prints the three level policies (design §6.3) for a
// JWT mount accessor from IRONBARK_DATA_PATH. It is the lab's stand-in for
// `ironbark render-policies` (plan task 4.3) and shares its implementation
// (internal/levels.RenderPolicies), so the lab fixture never re-implements the
// policies.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/levels"
)

func main() {
	acc := flag.String("accessor", "", "JWT auth mount accessor")
	flag.Parse()
	if *acc == "" {
		fmt.Fprintln(os.Stderr, "renderpolicies: -accessor is required")
		os.Exit(2)
	}
	t, err := grantcfg.ParseTemplate(os.Getenv("IRONBARK_DATA_PATH"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "renderpolicies:", err)
		os.Exit(2)
	}
	p, e, tg := levels.RenderPolicies(t, *acc)
	fmt.Print(p, e, tg)
}
