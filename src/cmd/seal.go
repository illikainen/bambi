package cmd

import (
	"os"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sealOpts struct {
	input  flag.PathSlice
	output flag.Path
}

var sealCmd = &cobra.Command{
	Use:   "seal [flags] <file>...",
	Short: "Encrypt and sign an archive",
	Run: func(cmd *cobra.Command, args []string) {
		err := sealRun(cmd, args)
		if err != nil {
			log.Tracef("%+v", err)
			log.Fatalf("%s", err)
		}
	},
	Args: sealArgs,
}

func init() {
	flags := sealCmd.Flags()

	sealOpts.input.State = flag.MustExist
	flags.VarP(&sealOpts.input, "input", "i", "Input file(s) to seal")
	lo.Must0(flags.MarkHidden("input"))

	sealOpts.output.State = flag.MustNotExist
	sealOpts.output.Mode = flag.ReadWriteMode
	flags.VarP(&sealOpts.output, "output", "o", "Output file for the sealed blob")
	lo.Must0(sealCmd.MarkFlagRequired("output"))

	rootCmd.AddCommand(sealCmd)
}

func sealArgs(cmd *cobra.Command, args []string) error {
	if len(args) <= 0 {
		return errors.Errorf("no files to seal")
	}

	flags := cmd.Flags()
	input := flags.Lookup("input")
	for _, arg := range args {
		err := input.Value.Set(arg)
		if err != nil {
			return err
		}
	}

	return nil
}

func sealRun(_ *cobra.Command, args []string) (err error) {
	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	output, err := os.Create(sealOpts.output.String())
	if err != nil {
		return err
	}
	defer errorx.Defer(output.Close, &err)

	blobber, err := blob.NewWriter(output, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: true,
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

	log.Infof("successfully wrote sealed blob to %s", sealOpts.output.String())
	return nil
}
