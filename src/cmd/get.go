package cmd

import (
	"os"
	"path/filepath"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-utils/src/cobrax"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var getOpts struct {
	url     flag.URL
	output  flag.Path
	extract flag.Path
}

var getCmd = &cobra.Command{
	Use:     "get [flags] <url>",
	Short:   "Download and verify a signed and encrypted archive",
	PreRunE: getPreRun,
	Run:     cobrax.Run(getRun),
	Args:    getArgs,
}

func init() {
	flags := getCmd.Flags()

	flags.Var(&getOpts.url, "url", "URL to download")
	lo.Must0(flags.MarkHidden("url"))

	getOpts.output.State = flag.MustNotExist
	getOpts.output.Mode = flag.ReadWriteMode
	flags.VarP(&getOpts.output, "output", "o", "Output file for the downloaded archive")

	getOpts.extract.State = flag.MustNotExist | flag.MustBeDir
	getOpts.extract.Mode = flag.ReadWriteMode
	flags.VarP(&getOpts.extract, "extract", "e", "Extract the downloaded archive to this directory")

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

func getPreRun(_ *cobra.Command, _ []string) error {
	if getOpts.output.String() == "" && getOpts.extract.String() == "" {
		return errors.Errorf("--output and/or --extract is required")
	}

	return nil
}

func getRun(_ *cobra.Command, _ []string) (err error) {
	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	output := getOpts.output.String()
	if output == "" {
		tmpDir, tmpClean, err := iofs.MkdirTemp()
		if err != nil {
			return err
		}
		defer errorx.Defer(tmpClean, &err)

		output = filepath.Join(tmpDir, "blob")
	}

	f, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304
	defer errorx.Defer(f.Close, &err)

	blobber, err := blob.Download(getOpts.url.Value, f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: true,
	})
	if err != nil {
		return err
	}

	if getOpts.output.String() != "" {
		log.Infof("successfully wrote sealed blob from %s to %s", getOpts.url.Value, getOpts.output.String())
	}

	if getOpts.extract.String() != "" {
		arch, err := archive.NewReader(blobber)
		if err != nil {
			return err
		}

		err = arch.ExtractAll(getOpts.extract.String())
		if err != nil {
			return err
		}

		log.Infof("successfully extracted sealed blob to %s", getOpts.extract.String())
	}

	return nil
}
