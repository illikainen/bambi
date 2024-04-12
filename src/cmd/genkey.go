package cmd

import (
	"fmt"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var genkeyOpts struct {
	cryptor.GenerateKeyOptions
}

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a keypair",
	Run: func(cmd *cobra.Command, args []string) {
		err := genkeyRun(cmd, args)
		if err != nil {
			log.Tracef("%+v", err)
			log.Fatalf("%s", err)
		}
	},
}

func init() {
	flags := cryptor.GenerateKeyFlags(cryptor.GenerateKeyConfig{
		Options: &genkeyOpts.GenerateKeyOptions,
	})
	genkeyCmd.Flags().AddFlagSet(flags)
	lo.Must0(genkeyCmd.MarkFlagRequired("output"))

	rootCmd.AddCommand(genkeyCmd)
}

func genkeyRun(_ *cobra.Command, _ []string) error {
	pubKey, privKey, err := asymmetric.GenerateKey()
	if err != nil {
		return err
	}

	pubFile := fmt.Sprintf("%s.pub", genkeyOpts.Output)
	err = pubKey.Write(pubFile)
	if err != nil {
		return err
	}

	privFile := fmt.Sprintf("%s.priv", genkeyOpts.Output)
	err = privKey.Write(privFile)
	if err != nil {
		return err
	}

	log.Infof("successfully wrote %s to %s and %s", pubKey.Fingerprint(), pubFile, privFile)
	return nil
}
