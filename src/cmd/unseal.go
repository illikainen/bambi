package cmd

import (
	"os"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var unsealOpts struct {
	input      flag.Path
	output     flag.Path
	signedOnly bool
}

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Verify and decrypt an archive",
	Run: func(cmd *cobra.Command, args []string) {
		err := unsealRun(cmd, args)
		if err != nil {
			log.Tracef("%+v", err)
			log.Fatalf("%s", err)
		}
	},
}

func init() {
	flags := unsealCmd.Flags()

	unsealOpts.input.State = flag.MustExist
	flags.VarP(&unsealOpts.input, "input", "i", "File to unseal")
	lo.Must0(unsealCmd.MarkFlagRequired("input"))

	unsealOpts.output.State = flag.MustBeDir
	unsealOpts.output.Mode = flag.ReadWriteMode
	flags.VarP(&unsealOpts.output, "output", "o", "Output file for the unsealed blob")
	lo.Must0(unsealCmd.MarkFlagRequired("output"))

	flags.BoolVarP(&unsealOpts.signedOnly, "signed-only", "s", false,
		"Required if the archive is signed but not encrypted")

	rootCmd.AddCommand(unsealCmd)
}

func unsealRun(_ *cobra.Command, _ []string) (err error) {
	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	f, err := os.Open(unsealOpts.input.String())
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

	err = arch.ExtractAll(unsealOpts.output.String())
	if err != nil {
		return err
	}

	log.Infof("successfully wrote unsealed blob to %s", unsealOpts.output.String())

	return nil
}
