package cmd

import (
	"net/url"
	"os"

	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-netutils/src/sshx"
	"github.com/illikainen/go-utils/src/errorx"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var putOpts struct {
	url        *url.URL
	signedOnly bool
}

var putCmd = &cobra.Command{
	Use:   "put [flags] <url> <file>",
	Short: "Upload a sealed archive",
	Long: "Upload a sealed archive.\n\n" +
		"The file provided after <url> is verified as a signed and encrypted archive\n" +
		"before uploading it to <url>.\n",
	Args:    cobra.ExactArgs(2),
	PreRunE: putPreRun,
	RunE:    putRun,
}

func init() {
	flags := putCmd.Flags()

	flags.BoolVarP(&putOpts.signedOnly, "signed-only", "s", false,
		"Required if the archive is signed but not encrypted")

	rootCmd.AddCommand(putCmd)
}

func putPreRun(_ *cobra.Command, args []string) error {
	ro, rw, err := sshx.SandboxPaths()
	if err != nil {
		return err
	}
	ro = append(ro, args[1])

	uri, err := url.Parse(args[0])
	if err != nil {
		return err
	}
	putOpts.url = uri

	if uri.Scheme == "file" {
		rw = append(rw, uri.Path)
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

func putRun(cmd *cobra.Command, args []string) error {
	cmd.SilenceUsage = true

	keys, err := blob.ReadKeyring(rootOpts.privKey, rootOpts.pubKeys)
	if err != nil {
		return err
	}

	f, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	err = blob.Upload(putOpts.url, f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: !putOpts.signedOnly,
	})
	if err != nil {
		return err
	}

	log.Infof("successfully uploaded sealed blob to %s", putOpts.url)
	return nil
}
