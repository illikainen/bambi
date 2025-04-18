package cmd

import (
	"os"

	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-utils/src/cobrax"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var getOpts struct {
	url        flag.URL
	output     flag.Path
	signedOnly bool
}

var getCmd = &cobra.Command{
	Use:   "get [flags] <url>",
	Short: "Download and verify a signed and encrypted archive",
	Run:   cobrax.Run(getRun),
	Args:  getArgs,
}

func init() {
	flags := getCmd.Flags()

	flags.Var(&getOpts.url, "url", "URL to download")
	lo.Must0(flags.MarkHidden("url"))

	getOpts.output.State = flag.MustNotExist
	getOpts.output.Mode = flag.ReadWriteMode
	flags.VarP(&getOpts.output, "output", "o", "Output file for the downloaded archive")
	lo.Must0(getCmd.MarkFlagRequired("output"))

	flags.BoolVarP(&getOpts.signedOnly, "signed-only", "s", false,
		"Required if the archive is signed but not encrypted")

	rootCmd.AddCommand(getCmd)
}

func getArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.Errorf("no URL provided")
	}

	flags := cmd.Flags()
	uri := flags.Lookup("url")
	err := uri.Value.Set(args[0])
	if err != nil {
		return err
	}

	return nil
}

func getRun(_ *cobra.Command, _ []string) (err error) {
	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	f, err := os.OpenFile(getOpts.output.String(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304
	defer errorx.Defer(f.Close, &err)

	blobber, err := blob.Download(getOpts.url.Value, f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: !getOpts.signedOnly,
	})
	if err != nil {
		return err
	}

	log.Infof("signed by: %s", blobber.Signer)
	log.Infof("sha2-256: %s", blobber.Metadata.Hashes.SHA256)
	log.Infof("sha3-512: %s", blobber.Metadata.Hashes.KECCAK512)
	log.Infof("blake2b-512: %s", blobber.Metadata.Hashes.BLAKE2b512)
	log.Infof("successfully wrote sealed blob from %s to %s", getOpts.url.Value, getOpts.output.String())
	return nil
}
