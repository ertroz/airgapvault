package main

import (
	"os"

	"github.com/airgap/airgapvault/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
