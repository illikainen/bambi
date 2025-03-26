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

var putOpts struct {
	url   flag.URL
	input flag.Path
}

var putCmd = &cobra.Command{
	Use:   "put [flags] <url> <file>",
	Short: "Upload a sealed archive",
	Long: "Upload a sealed archive.\n\n" +
		"The file provided after <url> is verified as a signed and encrypted archive\n" +
		"before uploading it to <url>.\n",
	Run:  cobrax.Run(putRun),
	Args: putArgs,
}

func init() {
	flags := putCmd.Flags()

	flags.Var(&putOpts.url, "url", "URL to upload")
	lo.Must0(flags.MarkHidden("url"))

	putOpts.input.State = flag.MustExist
	flags.VarP(&putOpts.input, "input", "i", "File to upload")
	lo.Must0(flags.MarkHidden("input"))

	rootCmd.AddCommand(putCmd)
}

func putArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		return errors.Errorf("no URL and/or file provided")
	}

	flags := cmd.Flags()
	uri := flags.Lookup("url")
	err := uri.Value.Set(args[0])
	if err != nil {
		return err
	}

	input := flags.Lookup("input")
	err = input.Value.Set(args[1])
	if err != nil {
		return err
	}

	return nil
}

func putRun(_ *cobra.Command, _ []string) error {
	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	f, err := os.Open(putOpts.input.String())
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	err = blob.Upload(putOpts.url.Value, f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: true,
	})
	if err != nil {
		return err
	}

	log.Infof("successfully uploaded sealed blob to %s", putOpts.url.Value)
	return nil
}
