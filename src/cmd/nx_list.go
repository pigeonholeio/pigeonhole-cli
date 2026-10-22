package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/pigeonholeio/pigeonhole-cli/nx"
	"github.com/spf13/cobra"
)

var nxListCmd = &cobra.Command{
	Use:         "list",
	Aliases:     []string{"ls"},
	Short:       "List your available secrets",
	Annotations: map[string]string{"skip-pre-run": "true"},
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := nx.LoadIdentity()
		if err != nil {
			return err
		}
		metas, err := nx.List(id.Token, "")
		if err != nil {
			return err
		}
		if len(metas) == 0 {
			fmt.Println("No secrets.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "REFERENCE\tID\tONETIME\tUPLOADED")
		for _, m := range metas {
			fmt.Fprintf(w, "%s\t%s\t%v\t%v\n", m.Reference, m.ID, m.Onetime, m.Uploaded)
		}
		return w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(nxListCmd)
}
