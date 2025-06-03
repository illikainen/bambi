package cmd

import (
	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var convertKeyOpts struct {
	input   string
	output  string
	private bool
}

var convertKeyCmd = &cobra.Command{
	Use:     "convert-key",
	Short:   "Convert a key to the new storage format",
	PreRunE: convertKeyPreRun,
	RunE:    convertKeyRun,
	Hidden:  true,
}

func init() {
	flags := convertKeyCmd.Flags()

	flags.StringVarP(&convertKeyOpts.input, "input", "i", "", "Key to fingerprint")
	lo.Must0(convertKeyCmd.MarkFlagRequired("input"))

	flags.StringVarP(&convertKeyOpts.output, "output", "o", "", "Output file for the converted key")
	lo.Must0(convertKeyCmd.MarkFlagRequired("output"))

	flags.BoolVarP(&convertKeyOpts.private, "private", "P", false, "Treat the key as a private key")

	rootCmd.AddCommand(convertKeyCmd)
}

func convertKeyPreRun(_ *cobra.Command, _ []string) error {
	err := rootOpts.Sandbox.AddReadOnlyPath(convertKeyOpts.input)
	if err != nil {
		return err
	}

	err = rootOpts.Sandbox.AddReadWritePath(convertKeyOpts.output)
	if err != nil {
		return err
	}

	return rootOpts.Sandbox.Confine()
}

func convertKeyRun(cmd *cobra.Command, _ []string) (err error) {
	cmd.SilenceUsage = true

	fingerprint := ""
	if convertKeyOpts.private {
		key, err := asymmetric.ReadPrivateKeyLegacy(convertKeyOpts.input)
		if err != nil {
			return err
		}

		fingerprint = key.Fingerprint()
		err = key.Write(convertKeyOpts.output)
		if err != nil {
			return err
		}
	} else {
		key, err := asymmetric.ReadPublicKeyLegacy(convertKeyOpts.input)
		if err != nil {
			return err
		}

		fingerprint = key.Fingerprint()
		err = key.Write(convertKeyOpts.output)
		if err != nil {
			return err
		}
	}

	log.Infof("fingerprint: %s", fingerprint)
	log.Infof("successfully converted %s to %s", convertKeyOpts.input, convertKeyOpts.output)
	return nil
}
