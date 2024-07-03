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

var unsealOpts struct {
	cryptor.DecryptOptions
}

var undealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Verify and decrypt an archive",
	Run: func(cmd *cobra.Command, args []string) {
		err := unsealRun(cmd, args)
		if err != nil {
			log.Tracef("%+v", err)
			log.Fatalf("%s", err)
		}
	},
}

func init() {
	flags := cryptor.DecryptFlags(cryptor.DecryptConfig{
		Options: &unsealOpts.DecryptOptions,
	})
	undealCmd.Flags().AddFlagSet(flags)
	lo.Must0(undealCmd.MarkFlagRequired("input"))

	rootCmd.AddCommand(undealCmd)
}

func unsealRun(_ *cobra.Command, _ []string) (err error) {
	conf, err := config.Read(rootOpts.config)
	if err != nil {
		return err
	}

	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		ro := []string{unsealOpts.Input}
		rw := []string{}

		confRO, confRW, err := conf.SandboxPaths()
		if err != nil {
			return err
		}
		ro = append(ro, confRO...)
		rw = append(rw, confRW...)

		// Required to mount the file in the sandbox.
		if unsealOpts.Output != "" {
			f, err := os.Create(unsealOpts.Output)
			if err != nil {
				return err
			}

			err = f.Close()
			if err != nil {
				return err
			}

			rw = append(rw, unsealOpts.Output)
		}

		// See ^
		if unsealOpts.Extract != "" {
			err := os.Mkdir(unsealOpts.Extract, 0700)
			if err != nil {
				return err
			}

			rw = append(rw, unsealOpts.Extract)
		}

		_, err = sandbox.Exec(sandbox.Options{
			Command: os.Args,
			RO:      ro,
			RW:      rw,
			Stdout:  process.LogrusOutput,
			Stderr:  process.LogrusOutput,
		})
		if err != nil {
			var outErr error
			if unsealOpts.Output != "" {
				outErr = os.Remove(unsealOpts.Output)
			}

			var extErr error
			if unsealOpts.Extract != "" {
				extErr = os.RemoveAll(unsealOpts.Extract)
			}

			return errorx.Join(err, outErr, extErr)
		}
	}

	keys, err := conf.ReadKeyring()
	if err != nil {
		return err
	}

	cipherBlob, err := blob.New(blob.Config{
		Type: metadata.Name(),
		Path: unsealOpts.Input,
		Keys: keys,
	})
	if err != nil {
		return err
	}

	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return err
	}
	defer errorx.Defer(tmpClean, &err)

	tmpCiphertext := filepath.Join(tmpDir, "ciphertext")
	meta, err := cipherBlob.Verify(tmpCiphertext)
	if err != nil {
		return err
	}

	if !meta.Encrypted {
		return errors.Errorf("%s: not encrypted", unsealOpts.Input)
	}

	if unsealOpts.Extract != "" {
		tmpPlaintext := filepath.Join(tmpDir, "plaintext")
		err := cipherBlob.Decrypt(tmpCiphertext, tmpPlaintext, meta.Keys)
		if err != nil {
			return err
		}

		arch, err := archive.Open(tmpPlaintext)
		if err != nil {
			return err
		}

		err = arch.ExtractAll(unsealOpts.Extract)
		if err != nil {
			return err
		}

		log.Infof("successfully extracted unsealed blob to %s", unsealOpts.Extract)
	}

	if unsealOpts.Output != "" {
		err = cipherBlob.Decrypt(tmpCiphertext, unsealOpts.Output, meta.Keys)
		if err != nil {
			return err
		}

		log.Infof("successfully wrote unsealed blob to %s", unsealOpts.Output)
	}

	return nil
}
