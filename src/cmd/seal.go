package cmd

import (
	"os"
	"path/filepath"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/config"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
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

	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		ro := []string{}
		rw := []string{sealOpts.Output}

		confRO, confRW, err := conf.SandboxPaths()
		if err != nil {
			return err
		}
		ro = append(ro, confRO...)
		rw = append(rw, confRW...)

		// Required to mount the file in the sandbox.
		f, err := os.Create(sealOpts.Output)
		if err != nil {
			return err
		}

		err = f.Close()
		if err != nil {
			return err
		}

		_, err = sandbox.Exec(sandbox.Options{
			Command: os.Args,
			RO:      append(ro, args...),
			RW:      rw,
			Stdout:  process.LogrusOutput,
			Stderr:  process.LogrusOutput,
		})
		return err
	}

	keys, err := conf.ReadKeyring()
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
		Type: metadata.Name(),
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
