package cmd

import (
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

var getOpts struct {
	transport.DownloadOptions
}

var getCmd = &cobra.Command{
	Use:     "get [flags] <url>",
	Short:   "Download and verify a signed and encrypted archive",
	PreRunE: getPreRun,
	Run:     cobrax.Run(getRun),
	Args:    cobrax.ValidateArgsLength(1, 1),
}

func init() {
	flags := transport.DownloadFlags(transport.DownloadConfig{
		Options: &getOpts.DownloadOptions,
	})
	getCmd.Flags().AddFlagSet(flags)

	rootCmd.AddCommand(getCmd)
}

func getPreRun(_ *cobra.Command, _ []string) error {
	if getOpts.Output == "" && getOpts.Extract == "" {
		return errors.Errorf("--output and/or --extract is required")
	}

	return nil
}

func getRun(_ *cobra.Command, args []string) (err error) {
	keys, err := blob.ReadKeyring(rootOpts.privKey.String(), rootOpts.pubKeys.StringSlice())
	if err != nil {
		return err
	}

	uri, err := url.Parse(args[0])
	if err != nil {
		return err
	}

	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		ro := []string{}
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
			ro = append(ro, uri.Path)
		}

		// Required to mount the file in the sandbox.
		if getOpts.Output != "" {
			f, err := os.Create(getOpts.Output)
			if err != nil {
				return err
			}

			err = f.Close()
			if err != nil {
				return err
			}

			rw = append(rw, getOpts.Output)
		}

		// See ^
		if getOpts.Extract != "" {
			err := os.Mkdir(getOpts.Extract, 0700)
			if err != nil {
				return err
			}

			rw = append(rw, getOpts.Extract)
		}

		_, err = sandbox.Exec(sandbox.Options{
			Command: os.Args,
			RO:      ro,
			RW:      rw,
			Share:   sandbox.ShareNet,
			Stdout:  process.LogrusOutput,
			Stderr:  process.LogrusOutput,
		})
		if err != nil {
			var outErr error
			if getOpts.Output != "" {
				outErr = os.Remove(getOpts.Output)
			}

			var extErr error
			if getOpts.Extract != "" {
				extErr = os.RemoveAll(getOpts.Extract)
			}

			return errorx.Join(err, outErr, extErr)
		}

		return nil
	}

	output := getOpts.Output
	if output == "" {
		tmpDir, tmpClean, err := iofs.MkdirTemp()
		if err != nil {
			return err
		}
		defer errorx.Defer(tmpClean, &err)

		output = filepath.Join(tmpDir, "blob")
	}

	f, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304
	defer errorx.Defer(f.Close, &err)

	blobber, err := blob.Download(uri, f, &blob.Options{
		Type:      metadata.Name(),
		Keyring:   keys,
		Encrypted: true,
	})
	if err != nil {
		return err
	}

	if getOpts.Output != "" {
		log.Infof("successfully wrote sealed blob from %s to %s", uri, getOpts.Output)
	}

	if getOpts.Extract != "" {
		arch, err := archive.NewReader(blobber)
		if err != nil {
			return err
		}

		err = arch.ExtractAll(getOpts.Extract)
		if err != nil {
			return err
		}

		log.Infof("successfully extracted sealed blob to %s", getOpts.Extract)
	}

	return nil
}
