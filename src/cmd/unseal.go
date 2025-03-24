package cmd

import (
	"io"
	"os"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/config"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
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
		extractDirCreated := false
		if unsealOpts.Extract != "" {
			exists, err := iofs.Exists(unsealOpts.Extract)
			if err != nil {
				return err
			}

			if !exists {
				err := os.Mkdir(unsealOpts.Extract, 0700)
				if err != nil {
					return err
				}
				extractDirCreated = true
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
			if unsealOpts.Extract != "" && extractDirCreated {
				extErr = os.RemoveAll(unsealOpts.Extract)
			}

			return errorx.Join(err, outErr, extErr)
		}
		return nil
	}

	keys, err := conf.ReadKeyring()
	if err != nil {
		return err
	}

	f, err := os.Open(unsealOpts.Input)
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	blobber, err := blob.NewReader(f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: true,
	})
	if err != nil {
		return err
	}

	if unsealOpts.Extract != "" {
		arch, err := archive.NewReader(blobber)
		if err != nil {
			return err
		}
		defer errorx.Defer(arch.Close, &err)

		err = arch.ExtractAll(unsealOpts.Extract)
		if err != nil {
			return err
		}

		log.Infof("successfully extracted unsealed blob to %s", unsealOpts.Extract)
	}

	if unsealOpts.Output != "" {
		outf, err := os.Create(unsealOpts.Output)
		if err != nil {
			return err
		}
		defer errorx.Defer(outf.Close, &err)

		_, err = io.Copy(outf, blobber)
		if err != nil {
			return err
		}

		log.Infof("successfully wrote unsealed blob to %s", unsealOpts.Output)
	}

	return nil
}
