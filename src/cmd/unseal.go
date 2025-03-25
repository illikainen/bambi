package cmd

import (
	"io"
	"os"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var unsealOpts struct {
	input   flag.Path
	output  flag.Path
	extract flag.Path
}

var unsealCmd = &cobra.Command{
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
	flags := unsealCmd.Flags()

	unsealOpts.input.State = flag.MustExist
	flags.VarP(&unsealOpts.input, "input", "i", "File to unseal")
	lo.Must0(unsealCmd.MarkFlagRequired("input"))

	unsealOpts.output.State = flag.MustNotExist
	flags.VarP(&unsealOpts.output, "output", "o", "Output file for the unsealed blob")

	flags.VarP(&unsealOpts.extract, "extract", "e", "Extract the unsealed blob to this directory")

	rootCmd.AddCommand(unsealCmd)
}

func unsealRun(_ *cobra.Command, _ []string) (err error) {
	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		ro := []string{unsealOpts.input.String()}
		rw := []string{}

		confRO, confRW, err := rootOpts.config.SandboxPaths()
		if err != nil {
			return err
		}
		ro = append(ro, confRO...)
		rw = append(rw, confRW...)

		// Required to mount the file in the sandbox.
		if unsealOpts.output.String() != "" {
			f, err := os.Create(unsealOpts.output.String())
			if err != nil {
				return err
			}

			err = f.Close()
			if err != nil {
				return err
			}

			rw = append(rw, unsealOpts.output.String())
		}

		// See ^
		extractDirCreated := false
		if unsealOpts.extract.String() != "" {
			exists, err := iofs.Exists(unsealOpts.extract.String())
			if err != nil {
				return err
			}

			if !exists {
				err := os.Mkdir(unsealOpts.extract.String(), 0700)
				if err != nil {
					return err
				}
				extractDirCreated = true
			}

			rw = append(rw, unsealOpts.extract.String())
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
			if unsealOpts.output.String() != "" {
				outErr = os.Remove(unsealOpts.output.String())
			}

			var extErr error
			if unsealOpts.extract.String() != "" && extractDirCreated {
				extErr = os.RemoveAll(unsealOpts.extract.String())
			}

			return errorx.Join(err, outErr, extErr)
		}
		return nil
	}

	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	f, err := os.Open(unsealOpts.input.String())
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

	if unsealOpts.extract.String() != "" {
		arch, err := archive.NewReader(blobber)
		if err != nil {
			return err
		}
		defer errorx.Defer(arch.Close, &err)

		err = arch.ExtractAll(unsealOpts.extract.String())
		if err != nil {
			return err
		}

		log.Infof("successfully extracted unsealed blob to %s", unsealOpts.extract)
	}

	if unsealOpts.output.String() != "" {
		outf, err := os.Create(unsealOpts.output.String())
		if err != nil {
			return err
		}
		defer errorx.Defer(outf.Close, &err)

		_, err = io.Copy(outf, blobber)
		if err != nil {
			return err
		}

		log.Infof("successfully wrote unsealed blob to %s", unsealOpts.output)
	}

	return nil
}
