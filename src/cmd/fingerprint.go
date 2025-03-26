package cmd

import (
	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-utils/src/cobrax"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var fingerprintOpts struct {
	input   flag.Path
	private bool
}

var fingerprintCmd = &cobra.Command{
	Use:   "fingerprint",
	Short: "Show the fingerprint for a key",
	Run:   cobrax.Run(fingerprintRun),
}

func init() {
	flags := fingerprintCmd.Flags()

	fingerprintOpts.input.State = flag.MustExist
	flags.VarP(&fingerprintOpts.input, "input", "i", "Key to fingerprint")
	lo.Must0(fingerprintCmd.MarkFlagRequired("input"))

	flags.BoolVarP(&fingerprintOpts.private, "private", "P", false, "Treat the key as a private key")

	rootCmd.AddCommand(fingerprintCmd)
}

func fingerprintRun(_ *cobra.Command, _ []string) error {
	fingerprint := ""
	if fingerprintOpts.private {
		key, err := asymmetric.ReadPrivateKey(fingerprintOpts.input.String())
		if err != nil {
			return err
		}

		fingerprint = key.Fingerprint()
	} else {
		key, err := asymmetric.ReadPublicKey(fingerprintOpts.input.String())
		if err != nil {
			return err
		}

		fingerprint = key.Fingerprint()
	}

	log.Infof("fingerprint for %s is %s", fingerprintOpts.input.String(), fingerprint)
	return nil
}
