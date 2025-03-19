package cmd

import (
	"os"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-utils/src/cobrax"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var fingerprintOpts struct {
	input   string
	private bool
}

var fingerprintCmd = &cobra.Command{
	Use:   "fingerprint",
	Short: "Show the fingerprint for a key",
	Run:   cobrax.Run(fingerprintRun),
}

func init() {
	flags := fingerprintCmd.Flags()

	flag.PathVarP(
		flags,
		&fingerprintOpts.input,
		"input",
		"i",
		flag.Path{State: flag.MustExist},
		"Key to fingerprint",
	)
	lo.Must0(fingerprintCmd.MarkFlagRequired("input"))

	flags.BoolVarP(
		&fingerprintOpts.private,
		"private",
		"p",
		false,
		"Treat the key as a private key",
	)

	rootCmd.AddCommand(fingerprintCmd)
}

func fingerprintRun(_ *cobra.Command, _ []string) error {
	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		_, err := sandbox.Exec(sandbox.Options{
			Command: os.Args,
			RO:      []string{fingerprintOpts.input},
			Stdout:  process.LogrusOutput,
			Stderr:  process.LogrusOutput,
		})
		return err
	}

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
