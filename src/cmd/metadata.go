package cmd

import (
	"encoding/json"
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

var metadataOpts struct {
	input      flag.Path
	output     flag.Path
	signedOnly bool
}

var metadataCmd = &cobra.Command{
	Use:    "metadata",
	Short:  "Show the metadata for a signed and optionally encrypted archive",
	Run:    cobrax.Run(metadataRun),
	Hidden: true,
}

func init() {
	flags := metadataCmd.Flags()

	metadataOpts.input.State = flag.MustExist
	flags.VarP(&metadataOpts.input, "input", "i", "File to verify")
	lo.Must0(metadataCmd.MarkFlagRequired("input"))

	metadataOpts.output.State = flag.MustNotExist
	metadataOpts.output.Mode = flag.ReadWriteMode
	flags.VarP(&metadataOpts.output, "output", "o", "Output file for the verified blob")

	flags.BoolVarP(&metadataOpts.signedOnly, "signed-only", "s", false,
		"Required if the archive is signed but not encrypted")

	rootCmd.AddCommand(metadataCmd)
}

func metadataRun(_ *cobra.Command, _ []string) (err error) {
	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	f, err := os.Open(metadataOpts.input.String())
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	blobber, err := blob.NewReader(f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: !metadataOpts.signedOnly,
	})
	if err != nil {
		return err
	}

	meta, err := json.MarshalIndent(blobber.Metadata(), "", "    ")
	if err != nil {
		return err
	}
	meta = append(meta, '\n')

	log.Infof("%s", meta)
	if metadataOpts.output.String() != "" {
		f, err := os.Create(metadataOpts.output.String())
		if err != nil {
			return err
		}
		defer errorx.Defer(f.Close, &err)

		n, err := f.Write(meta)
		if err != nil {
			return err
		}
		if n != len(meta) {
			return errors.Errorf("invalid write size")
		}

		log.Infof("successfully wrote metadata to %s", metadataOpts.output.String())
	}

	return nil
}
