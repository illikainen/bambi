package cmd

import (
	"path/filepath"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/config"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sealOpts struct {
	cryptor.EncryptOptions
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
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) <= 0 {
			return errors.Errorf("no files to seal")
		}
		return nil
	},
}

func init() {
	flags := cryptor.EncryptFlags(cryptor.EncryptConfig{
		Options: &sealOpts.EncryptOptions,
	})
	lo.Must0(flags.MarkHidden("input"))

	sealCmd.Flags().AddFlagSet(flags)
	lo.Must0(sealCmd.MarkFlagRequired("output"))

	rootCmd.AddCommand(sealCmd)
}

func sealRun(_ *cobra.Command, args []string) (err error) {
	conf, err := config.Read(rootOpts.config)
	if err != nil {
		return err
	}

	keys, err := conf.ReadKeyrings()
	if err != nil {
		return err
	}

	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return err
	}
	defer errorx.Defer(tmpClean, &err)

	tmpArch := filepath.Join(tmpDir, "archive")
	arch, err := archive.Create(tmpArch)
	if err != nil {
		return err
	}

	err = arch.AddAll(args...)
	if err != nil {
		return errorx.Join(err, arch.Close())
	}

	err = arch.Close()
	if err != nil {
		return err
	}

	data, err := blob.New(blob.Config{
		Path: sealOpts.Output,
		Keys: keys,
	})
	if err != nil {
		return err
	}

	err = data.Import(tmpArch, nil)
	if err != nil {
		return err
	}

	err = data.Encrypt()
	if err != nil {
		return err
	}

	err = data.Sign()
	if err != nil {
		return err
	}

	log.Infof("successfully wrote sealed blob to %s", sealOpts.Output)
	return nil
}
