package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var statsCmd = &cobra.Command{
	Use:     "stats",
	Aliases: []string{"st"},
	Short:   "View your analytics and usage statistics",
	Long:    `View your analytics and usage statistics in YAML format.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Fetching analytics...")

		resp, err := PigeonHoleClient.GetUserAnalyticsWithResponse(GlobalCtx)
		if err != nil {
			logrus.Debugln(err.Error())
			fmt.Println("Failed to fetch analytics")
			return
		}

		if resp.JSON200 != nil {
			// Format the analytics data for YAML output
			analyticsOutput := map[string]interface{}{
				"analytics": map[string]interface{}{
					"secrets": map[string]interface{}{
						"sent":                    *resp.JSON200.Analytics.SecretsSent,
						"received":                *resp.JSON200.Analytics.SecretsReceived,
						"active_sent":             *resp.JSON200.Analytics.ActiveSecretsSent,
						"max_quota":               *resp.JSON200.Analytics.MaxSecretsQuota,
						"quota_used_percentage":   float64(*resp.JSON200.Analytics.ActiveSecretsSent) / float64(*resp.JSON200.Analytics.MaxSecretsQuota) * 100,
					},
					"data": map[string]interface{}{
						"total_bytes_sent":    *resp.JSON200.Analytics.TotalBytesSent,
						"max_bytes_quota":     *resp.JSON200.Analytics.MaxBytesQuota,
						"quota_used_percentage": float64(*resp.JSON200.Analytics.TotalBytesSent) / float64(*resp.JSON200.Analytics.MaxBytesQuota) * 100,
					},
				},
			}

			// Marshal to YAML
			yamlData, err := yaml.Marshal(analyticsOutput)
			if err != nil {
				logrus.Debugln(err.Error())
				fmt.Println("Failed to format analytics data")
				return
			}

			fmt.Println(string(yamlData))
		} else {
			fmt.Println("Failed to retrieve analytics")
		}
	},
}

func init() {
	secretsCmd.AddCommand(statsCmd)
}
