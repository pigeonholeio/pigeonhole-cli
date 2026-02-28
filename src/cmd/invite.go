package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"strings"

	"github.com/oapi-codegen/runtime/types"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Invite recipients to PigeonHole",
	Long: `Invite recipients to PigeonHole so they can receive your secrets.
Recipients will be sent an email with instructions to create an account.`,
	Run: func(cmd *cobra.Command, args []string) {
		recipient, _ := cmd.Flags().GetString("recipient")

		var recipients []string

		// If recipient flag provided, use it
		if recipient != "" {
			recipients = parseRecipients(recipient)
		} else {
			// Interactive mode
			recipients = promptForRecipients()
		}

		if len(recipients) == 0 {
			fmt.Println("❌ No recipients provided")
			return
		}

		// Show why we invite
		printInviteExplanation()

		// Confirm recipients
		fmt.Println("\n📋 Recipients to invite:")
		for _, r := range recipients {
			fmt.Printf("  • %s\n", r)
		}

		// Ask for confirmation
		fmt.Print("\n✓ Ready to send invitations? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.ToLower(strings.TrimSpace(response))

		if response != "yes" && response != "y" {
			fmt.Println("❌ Invitations cancelled")
			return
		}

		// Send invitations via API
		sendInvitations(recipients)
	},
}

// parseRecipients parses comma-separated email addresses
func parseRecipients(input string) []string {
	var recipients []string
	parts := strings.Split(input, ",")
	for _, part := range parts {
		email := strings.TrimSpace(part)
		if validateEmail(email) {
			recipients = append(recipients, email)
		} else {
			logrus.Warnf("Invalid email format: %s", email)
		}
	}
	return recipients
}

// promptForRecipients interactively prompts user for recipient emails
func promptForRecipients() []string {
	var recipients []string
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n📧 Enter recipient email addresses (one per line, or 'done' to finish):")

	for {
		fmt.Print("Email: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		if strings.ToLower(input) == "done" {
			break
		}

		if validateEmail(input) {
			recipients = append(recipients, input)
			fmt.Printf("✓ Added %s\n", input)
		} else {
			fmt.Printf("❌ Invalid email format: %s\n", input)
		}
	}

	return recipients
}

// validateEmail validates email format
func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// printInviteExplanation explains why we invite recipients
func printInviteExplanation() {
	fmt.Println("\n📌 Invite members before sending secrets:")
	fmt.Println("  • They'll create an account and upload their public key")
	fmt.Println("  • Guarantees secure delivery with end-to-end encryption")
}

// sendInvitations sends invitations via the API
func sendInvitations(recipients []string) {
	fmt.Printf("\n⏳ Sending invitations to %d recipient(s)...\n", len(recipients))

	// Convert string slice to types.Email slice
	emailRecipients := make([]types.Email, len(recipients))
	for i, r := range recipients {
		emailRecipients[i] = types.Email(r)
	}

	// Create request body using SDK types
	body := sdk.PostUserInviteJSONRequestBody{
		Recipients: emailRecipients,
	}

	// Send request via SDK client
	resp, err := PigeonHoleClient.PostUserInviteWithResponse(GlobalCtx, body)
	if err != nil {
		logrus.Errorf("Failed to send invitations: %v", err)
		fmt.Println("❌ Error: Failed to send invitations")
		return
	}

	// Handle response based on status code
	switch resp.StatusCode() {
	case http.StatusOK:
		fmt.Println("✅ Invitations sent successfully!")
		if resp.JSON200 != nil {
			fmt.Printf("📧 Invitations queued for %d recipient(s)\n", resp.JSON200.SentCount)
		}
	case http.StatusBadRequest:
		fmt.Println("❌ Error: Invalid request")
		if resp.JSON400 != nil && resp.JSON400.Message != nil {
			fmt.Printf("   %s\n", *resp.JSON400.Message)
		}
	case http.StatusUnauthorized:
		fmt.Println("❌ Error: Not authenticated. Please run 'pigeonhole auth login' first.")
	case http.StatusForbidden:
		fmt.Println("❌ Error: You don't have permission to send invitations")
		if resp.JSON403 != nil && resp.JSON403.Message != nil {
			fmt.Printf("   %s\n", *resp.JSON403.Message)
		}
	case http.StatusNotFound:
		fmt.Println("❌ Error: Endpoint not found")
	case http.StatusInternalServerError:
		fmt.Println("❌ Error: Server error")
		if resp.JSON500 != nil && resp.JSON500.Message != nil {
			fmt.Printf("   %s\n", *resp.JSON500.Message)
		}
	default:
		fmt.Printf("❌ Error: Unexpected response (status: %d)\n", resp.StatusCode())
	}
}

func init() {
	rootCmd.AddCommand(inviteCmd)

	inviteCmd.Flags().StringP("recipient", "r", "", "Comma-separated list of email addresses to invite")
}
