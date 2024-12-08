package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var docsCmd = &cobra.Command{
	Use: "docs",

	Short: "Opens the online docs",
	Long:  `Opens the online docs to get you some more help`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(`Need help or want to know more? 📚
Find the docs online at https://pigeono.io/docs  🚀`)
	},
}
var supportCmd = &cobra.Command{
	Use:   "support",
	Short: "Discover how you can help the project 🚀 🙌 ✨",
	Long:  `Find out how you can contribute to the project`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(`
🚀🫶 Thanks for your interest in supporting the project! 🫶 🚀
Here's how you can help:
- 🍺 Buy me a beer: Fuel my coding with your support!
- 🐛 Found a bug? Let's squash it together!
- 💻 Code Feedback: Got tips? Libraries I should try? Let me know!
- 💻 Code Contributions: Pull requests are always welcome!
- 🕵️  Let me know which Identity Provider you'd like to see supported next, Google? Okta? Keycloak?
- ❔ General feedback: Drop me a line at feedback@pigeono.io — I read every message!
- ⭐ A simple GitHub star will make my day!`)

	},
}

func init() {
	rootCmd.AddCommand(docsCmd)
	rootCmd.AddCommand(supportCmd)
}
