package cmd

import (
	"fmt"
	"time"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-utils/src/fn"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var genkeyOpts struct {
	output string
	delay  time.Duration
}

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a keypair",
	RunE:  genkeyRun,
}

func init() {
	flags := genkeyCmd.Flags()

	flags.StringVarP(&genkeyOpts.output, "output", "o", "",
		"Write the generated keypair to <output>.pub and <output>.priv")
	fn.Must(genkeyCmd.MarkFlagRequired("output"))

	flags.DurationVarP(&genkeyOpts.delay, "delay", "d", 60*time.Second,
		"Add a delay between each generated key")

	rootCmd.AddCommand(genkeyCmd)
}

func genkeyRun(_ *cobra.Command, _ []string) error {
	pubKey, privKey, err := asymmetric.GenerateKey(genkeyOpts.delay)
	if err != nil {
		return err
	}

	pubFile := fmt.Sprintf("%s.pub", genkeyOpts.output)
	err = pubKey.Write(pubFile)
	if err != nil {
		return err
	}

	privFile := fmt.Sprintf("%s.priv", genkeyOpts.output)
	err = privKey.Write(privFile)
	if err != nil {
		return err
	}

	log.Infof("successfully wrote %s to %s and %s", pubKey, pubFile, privFile)
	return nil
}
