package cmd

import (
	"os"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/fn"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sealOpts struct {
	output     string
	signedOnly bool
}

var sealCmd = &cobra.Command{
	Use:     "seal [flags] <file>...",
	Short:   "Encrypt and sign an archive",
	Args:    cobra.MinimumNArgs(1),
	PreRunE: sealPreRun,
	RunE:    sealRun,
}

func init() {
	flags := sealCmd.Flags()

	flags.StringVarP(&sealOpts.output, "output", "o", "", "Output file for the sealed blob")
	fn.Must(sealCmd.MarkFlagRequired("output"))

	flags.BoolVarP(&sealOpts.signedOnly, "signed-only", "s", false,
		"Only sign the archive, don't encrypt it")

	rootCmd.AddCommand(sealCmd)
}

func sealPreRun(_ *cobra.Command, args []string) error {
	err := rootOpts.Sandbox.AddReadOnlyPath(args...)
	if err != nil {
		return err
	}

	err = rootOpts.Sandbox.AddReadWritePath(sealOpts.output)
	if err != nil {
		return err
	}

	return rootOpts.Sandbox.Confine()
}

func sealRun(cmd *cobra.Command, args []string) (err error) {
	cmd.SilenceUsage = true

	keys, err := blob.ReadKeyring(rootOpts.PrivKey, rootOpts.PubKeys)
	if err != nil {
		return err
	}

	output, err := os.Create(sealOpts.output)
	if err != nil {
		return err
	}
	defer errorx.Defer(output.Close, &err)

	blobber, err := blob.NewWriter(output, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: !sealOpts.signedOnly,
	})
	if err != nil {
		return err
	}
	defer errorx.Defer(blobber.Close, &err)

	arch, err := archive.NewWriter(blobber)
	if err != nil {
		return err
	}
	defer errorx.Defer(arch.Close, &err)

	err = arch.AddAll(args...)
	if err != nil {
		return err
	}

	log.Infof("successfully wrote sealed blob to %s", sealOpts.output)
	return nil
}
