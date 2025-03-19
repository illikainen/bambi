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

var convertKeyOpts struct {
	input   string
	output  string
	private bool
}

var convertKeyCmd = &cobra.Command{
	Use:    "convert-key",
	Short:  "Convert a key to the new storage format",
	Run:    cobrax.Run(convertKeyRun),
	Hidden: true,
}

func init() {
	flags := convertKeyCmd.Flags()

	flag.PathVarP(
		flags,
		&convertKeyOpts.input,
		"input",
		"i",
		flag.Path{State: flag.MustExist},
		"Key to fingerprint",
	)
	lo.Must0(convertKeyCmd.MarkFlagRequired("input"))

	flag.PathVarP(
		flags,
		&convertKeyOpts.output,
		"output",
		"o",
		flag.Path{State: flag.MustNotExist},
		"Output file for the converted key",
	)
	lo.Must0(convertKeyCmd.MarkFlagRequired("output"))

	flags.BoolVarP(
		&convertKeyOpts.private,
		"private",
		"p",
		false,
		"Treat the key as a private key",
	)

	rootCmd.AddCommand(convertKeyCmd)
}

func convertKeyRun(_ *cobra.Command, _ []string) (err error) {
	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		// Required to mount the file in the sandbox.
		f, err := os.Create(convertKeyOpts.output)
		if err != nil {
			return err
		}

		err = f.Close()
		if err != nil {
			return err
		}

		_, err = sandbox.Exec(sandbox.Options{
			Command: os.Args,
			RO:      []string{convertKeyOpts.input},
			RW:      []string{convertKeyOpts.output},
			Stdout:  process.LogrusOutput,
			Stderr:  process.LogrusOutput,
		})
		return err
	}

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
