package cmd

import (
	"fmt"
	"time"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var genkeyOpts struct {
	output flag.Path
	delay  time.Duration
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
	flags := genkeyCmd.Flags()

	genkeyOpts.output.State = flag.MustNotExist
	genkeyOpts.output.Suffixes = []string{"pub", "priv"}
	flags.VarP(&genkeyOpts.output, "output", "o",
		"Write the generated keypair to <output>.pub and <output>.priv")
	lo.Must0(genkeyCmd.MarkFlagRequired("output"))

	flags.DurationVarP(&genkeyOpts.delay, "delay", "d", 60*time.Second,
		"Add a delay between each generated key")

	rootCmd.AddCommand(genkeyCmd)
}

func genkeyRun(_ *cobra.Command, _ []string) error {
	pubKey, privKey, err := asymmetric.GenerateKey(genkeyOpts.delay)
	if err != nil {
		return err
	}

	pubFile := fmt.Sprintf("%s.pub", genkeyOpts.output.String())
	err = pubKey.Write(pubFile)
	if err != nil {
		return err
	}

	privFile := fmt.Sprintf("%s.priv", genkeyOpts.output.String())
	err = privKey.Write(privFile)
	if err != nil {
		return err
	}

	log.Infof("successfully wrote %s to %s and %s", pubKey.Fingerprint(), pubFile, privFile)
	return nil
}
