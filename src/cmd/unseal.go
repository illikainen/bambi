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

var unsealOpts struct {
	input      string
	output     string
	signedOnly bool
}

var unsealCmd = &cobra.Command{
	Use:     "unseal",
	Short:   "Verify and decrypt an archive",
	PreRunE: unsealPreRun,
	RunE:    unsealRun,
}

func init() {
	flags := unsealCmd.Flags()

	flags.StringVarP(&unsealOpts.input, "input", "i", "", "File to unseal")
	fn.Must(unsealCmd.MarkFlagRequired("input"))

	flags.StringVarP(&unsealOpts.output, "output", "o", "", "Output file for the unsealed blob")
	fn.Must(unsealCmd.MarkFlagRequired("output"))

	flags.BoolVarP(&unsealOpts.signedOnly, "signed-only", "s", false,
		"Required if the archive is signed but not encrypted")

	rootCmd.AddCommand(unsealCmd)
}

func unsealPreRun(_ *cobra.Command, _ []string) error {
	err := rootOpts.Sandbox.AddReadOnlyPath(unsealOpts.input)
	if err != nil {
		return err
	}

	err = rootOpts.Sandbox.AddReadWritePath(unsealOpts.output)
	if err != nil {
		return err
	}

	return rootOpts.Sandbox.Confine()
}

func unsealRun(cmd *cobra.Command, _ []string) (err error) {
	cmd.SilenceUsage = true

	keys, err := blob.ReadKeyring(rootOpts.PrivKey, rootOpts.PubKeys)
	if err != nil {
		return err
	}

	f, err := os.Open(unsealOpts.input)
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	blobber, err := blob.NewReader(f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: !unsealOpts.signedOnly,
	})
	if err != nil {
		return err
	}
	log.Infof("signed by: %s", blobber.Signer)
	log.Infof("sha2-256: %s", blobber.Metadata.Hashes.SHA256)
	log.Infof("sha3-512: %s", blobber.Metadata.Hashes.KECCAK512)
	log.Infof("blake2b-512: %s", blobber.Metadata.Hashes.BLAKE2b512)

	arch, err := archive.NewReader(blobber)
	if err != nil {
		return err
	}
	defer errorx.Defer(arch.Close, &err)

	err = arch.ExtractAll(unsealOpts.output)
	if err != nil {
		return err
	}

	log.Infof("successfully wrote unsealed blob to %s", unsealOpts.output)

	return nil
}
