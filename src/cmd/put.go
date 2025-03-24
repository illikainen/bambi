package cmd

import (
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-netutils/src/sshx"
	"github.com/illikainen/go-netutils/src/transport"
	"github.com/illikainen/go-utils/src/cobrax"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var putOpts struct {
	transport.UploadOptions
}

var putCmd = &cobra.Command{
	Use: "put [flags] <url> [<file>...]",
	Long: "Upload a signed and encrypted archive.\n\n" +
		"If a file is provided with -i, the file is verified as a signed and\n" +
		"encrypted archive before being uploaded to <url>.  Otherwise, an\n" +
		"arbitrary number of files must be provided after <url>.  The files are\n" +
		"written to a signed and encrypted archive before being uploaded to to <url>.\n",
	Run:  cobrax.Run(putRun),
	Args: cobrax.ValidateArgsLength(1, -1),
}

func init() {
	flags := transport.UploadFlags(transport.UploadConfig{
		Options: &putOpts.UploadOptions,
	})
	putCmd.Flags().AddFlagSet(flags)

	rootCmd.AddCommand(putCmd)
}

func putRun(_ *cobra.Command, args []string) (err error) {
	keys, err := rootOpts.config.ReadKeyring()
	if err != nil {
		return err
	}

	uri, err := url.Parse(args[0])
	if err != nil {
		return err
	}

	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		ro := []string{putOpts.Input}
		rw := []string{}

		confRO, confRW, err := rootOpts.config.SandboxPaths()
		if err != nil {
			return err
		}
		ro = append(ro, confRO...)
		rw = append(rw, confRW...)

		sshRO, sshRW, err := sshx.SandboxPaths()
		if err != nil {
			return err
		}
		ro = append(ro, sshRO...)
		rw = append(rw, sshRW...)

		if uri.Scheme == "file" {
			f, err := os.Create(uri.Path)
			if err != nil {
				return err
			}

			err = f.Close()
			if err != nil {
				return err
			}

			rw = append(rw, uri.Path)
		}
		_, err = sandbox.Exec(sandbox.Options{
			Command: os.Args,
			RO:      ro,
			RW:      append(rw, args[1:]...),
			Share:   sandbox.ShareNet,
			Stdout:  process.LogrusOutput,
			Stderr:  process.LogrusOutput,
		})
		return err
	}

	if putOpts.Input != "" {
		f, err := os.Open(putOpts.Input)
		if err != nil {
			return err
		}
		defer errorx.Defer(f.Close, &err)

		err = blob.Upload(uri, f, &blob.Options{
			Type:      metadata.Name(),
			Keyring:   keys,
			Encrypted: true,
		})
		if err != nil {
			return err
		}
	} else {
		if len(args) < 2 {
			return errors.Errorf("no file(s) provided")
		}

		tmpDir, tmpClean, err := iofs.MkdirTemp()
		if err != nil {
			return err
		}
		defer errorx.Defer(tmpClean, &err)

		tmpFile, err := os.Create(filepath.Join(tmpDir, "archive")) // #nosec G304
		if err != nil {
			return err
		}
		defer errorx.Defer(tmpFile.Close, &err)

		blobber, err := blob.NewWriter(tmpFile, &blob.Options{
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

		err = arch.AddAll(args[1:]...)
		if err != nil {
			return err
		}

		err = blobber.Sign()
		if err != nil {
			return err
		}

		err = tmpFile.Sync()
		if err != nil {
			return err
		}

		_, err = iofs.Seek(tmpFile, 0, io.SeekStart)
		if err != nil {
			return err
		}

		err = blob.Upload(uri, tmpFile, &blob.Options{
			Type:      metadata.Name(),
			Keyring:   keys,
			Encrypted: true,
		})
		if err != nil {
			return err
		}
	}

	log.Infof("successfully uploaded sealed blob to %s", uri)
	return nil
}
