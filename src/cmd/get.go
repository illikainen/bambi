package cmd

import (
	"net/url"
	"os"

	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-netutils/src/sshx"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/fn"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var getOpts struct {
	url        *url.URL
	output     string
	signedOnly bool
}

var getCmd = &cobra.Command{
	Use:     "get [flags] <url>",
	Short:   "Download and verify a signed and encrypted archive",
	Args:    cobra.ExactArgs(1),
	PreRunE: getPreRun,
	RunE:    getRun,
}

func init() {
	flags := getCmd.Flags()

	flags.StringVarP(&getOpts.output, "output", "o", "", "Output file for the downloaded archive")
	fn.Must(getCmd.MarkFlagRequired("output"))

	flags.BoolVarP(&getOpts.signedOnly, "signed-only", "s", false,
		"Required if the archive is signed but not encrypted")

	rootCmd.AddCommand(getCmd)
}

func getPreRun(_ *cobra.Command, args []string) error {
	ro, rw, err := sshx.SandboxPaths()
	if err != nil {
		return err
	}
	rw = append(rw, getOpts.output)

	uri, err := url.Parse(args[0])
	if err != nil {
		return err
	}
	getOpts.url = uri

	if uri.Scheme == "file" {
		ro = append(ro, uri.Path)
	} else {
		rootOpts.Sandbox.SetShareNet(true)
	}

	err = rootOpts.Sandbox.AddReadOnlyPath(ro...)
	if err != nil {
		return err
	}

	err = rootOpts.Sandbox.AddReadWritePath(rw...)
	if err != nil {
		return err
	}

	return rootOpts.Sandbox.Confine()
}

func getRun(cmd *cobra.Command, _ []string) (err error) {
	cmd.SilenceUsage = true

	keys, err := blob.ReadKeyring(rootOpts.PrivKey, rootOpts.PubKeys)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(getOpts.output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	blobber, err := blob.Download(getOpts.url, f, &blob.Options{
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
	log.Infof("successfully wrote sealed blob from %s to %s", getOpts.url, getOpts.output)
	return nil
}
