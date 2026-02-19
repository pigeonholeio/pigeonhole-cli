/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	// "os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

// dashboardCmd represents the dashboard command
var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Open the PigeonHole web-based companion app",
	Long: `Open the PigeonHole dashboard in your default web browser.
The dashboard provides a web-based interface for posting secrets,
viewing analytics, and accessing additional features of PigeonHole.`,
	Run: func(cmd *cobra.Command, args []string) {
		url := "http://localhost:3000"
		fmt.Printf("Opening PigeonHole dashboard at %s...\n", url)

		err := openURL(url)
		if err != nil {
			fmt.Printf("Failed to open dashboard: %v\n", err)
			fmt.Printf("Please visit %s manually\n", url)
		} else {
			fmt.Println("Dashboard opened in your default browser!")
		}
	},
}

// openURL opens a URL in the default browser
func openURL(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		// macOS
		cmd = exec.Command("open", url)
	case "windows":
		// Windows
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		// Linux and other Unix-like systems
		cmd = exec.Command("xdg-open", url)
	}

	return cmd.Start()
}

func init() {
	rootCmd.AddCommand(dashboardCmd)
}
