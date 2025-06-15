package cmd

import (
	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-utils/src/fn"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var fingerprintOpts struct {
	input   string
	private bool
}

var fingerprintCmd = &cobra.Command{
	Use:     "fingerprint",
	Short:   "Show the fingerprint for a key",
	PreRunE: fingerprintPreRun,
	RunE:    fingerprintRun,
}

func init() {
	flags := fingerprintCmd.Flags()

	flags.StringVarP(&fingerprintOpts.input, "input", "i", "", "Key to fingerprint")
	fn.Must(fingerprintCmd.MarkFlagRequired("input"))

	flags.BoolVarP(&fingerprintOpts.private, "private", "P", false, "Treat the key as a private key")

	rootCmd.AddCommand(fingerprintCmd)
}

func fingerprintPreRun(_ *cobra.Command, _ []string) error {
	err := rootOpts.Sandbox.AddReadOnlyPath(fingerprintOpts.input)
	if err != nil {
		return err
	}

	return rootOpts.Sandbox.Confine()
}

func fingerprintRun(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	fingerprint := ""
	if fingerprintOpts.private {
		key, err := asymmetric.ReadPrivateKey(fingerprintOpts.input)
		if err != nil {
			return err
		}

		fingerprint = key.Fingerprint()
	} else {
		key, err := asymmetric.ReadPublicKey(fingerprintOpts.input)
		if err != nil {
			return err
		}

		fingerprint = key.Fingerprint()
	}

	log.Infof("fingerprint for %s is %s", fingerprintOpts.input, fingerprint)
	return nil
}
