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

		if resp.JSON200 != nil && resp.JSON200.Analytics != nil {
		analytics := resp.JSON200.Analytics
		if analytics.SecretsSent == nil || analytics.SecretsReceived == nil ||
			analytics.ActiveSecretsSent == nil || analytics.MaxSecretsQuota == nil ||
			analytics.TotalBytesSent == nil || analytics.MaxBytesQuota == nil {
			fmt.Println("Failed to retrieve complete analytics data")
			return
		}

		// Calculate percentages with divide-by-zero guards
		secretsQuotaPercent := 0.0
		if *analytics.MaxSecretsQuota > 0 {
			secretsQuotaPercent = float64(*analytics.ActiveSecretsSent) / float64(*analytics.MaxSecretsQuota) * 100
		}

		bytesQuotaPercent := 0.0
		if *analytics.MaxBytesQuota > 0 {
			bytesQuotaPercent = float64(*analytics.TotalBytesSent) / float64(*analytics.MaxBytesQuota) * 100
		}
			// Format the analytics data for YAML output
			analyticsOutput := map[string]interface{}{
				"analytics": map[string]interface{}{
					"secrets": map[string]interface{}{
						"sent":                    *analytics.SecretsSent,
						"received":                *analytics.SecretsReceived,
						"active_sent":             *analytics.ActiveSecretsSent,
						"max_quota":               *analytics.MaxSecretsQuota,
						"quota_used_percentage":   secretsQuotaPercent,
					},
					"data": map[string]interface{}{
						"total_bytes_sent":        *analytics.TotalBytesSent,
						"max_bytes_quota":         *analytics.MaxBytesQuota,
						"quota_used_percentage":   bytesQuotaPercent,
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
