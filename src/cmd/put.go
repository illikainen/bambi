package cmd

import (
	"net/url"
	"os"
	"path/filepath"

	"github.com/illikainen/bambi/src/archive"
	"github.com/illikainen/bambi/src/config"
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
	conf, err := config.Read(rootOpts.config)
	if err != nil {
		return err
	}

	keys, err := conf.ReadKeyring()
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

		confRO, confRW, err := conf.SandboxPaths()
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

	xfer, err := transport.New(uri)
	if err != nil {
		return err
	}
	defer errorx.Defer(xfer.Close, &err)

	data := &blob.Blob{}

	if putOpts.Input != "" {
		data, err = blob.New(blob.Config{
			Type:      metadata.Name(),
			Path:      putOpts.Input,
			Keys:      keys,
			Transport: xfer,
		})
		if err != nil {
			return err
		}

		meta, err := data.Verify("")
		if err != nil {
			return err
		}

		if !meta.Encrypted {
			return errors.Errorf("%s: not encrypted", putOpts.Input)
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

		tmpArch := filepath.Join(tmpDir, "archive")
		arch, err := archive.Create(tmpArch)
		if err != nil {
			return err
		}

		err = arch.AddAll(args[1:]...)
		if err != nil {
			return errorx.Join(err, arch.Close())
		}

		err = arch.Close()
		if err != nil {
			return err
		}

		data, err = blob.New(blob.Config{
			Type:      metadata.Name(),
			Path:      filepath.Join(tmpDir, "blob"),
			Keys:      keys,
			Transport: xfer,
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

		_, err = data.Verify("")
		if err != nil {
			return err
		}
	}

	err = data.Upload(uri.Path)
	if err != nil {
		return err
	}

	log.Infof("successfully uploaded sealed blob to %s", uri)
	return nil
}
