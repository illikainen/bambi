package cmd

import (
	"os"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-utils/src/errorx"
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
	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		ro := []string{}
		rw := []string{sealOpts.Output}

		confRO, confRW, err := rootOpts.config.SandboxPaths()
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

	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	output, err := os.Create(sealOpts.Output)
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

	log.Infof("successfully wrote sealed blob to %s", sealOpts.Output)
	return nil
}
