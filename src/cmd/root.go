package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/illikainen/bambi/src/config"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootOpts struct {
	configp   string
	config    *config.Config
	profile   string
	verbosity string
	privKey   string
	pubKeys   []string
	sandbox   string
	Sandbox   sandbox.Sandbox
}

var rootCmd = &cobra.Command{
	Use:     metadata.Name(),
	Version: metadata.Version(),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		err := rootPreRun(cmd, args)
		if err != nil {
			log.Tracef("%+v", err)
			log.Fatalf("%s", err)
		}
	},
}

func Command() *cobra.Command {
	return rootCmd
}

func init() {
	flags := rootCmd.PersistentFlags()
	flags.SortFlags = false

	levels := []string{}
	for _, level := range log.AllLevels {
		levels = append(levels, level.String())
	}

	flags.StringVarP(&rootOpts.configp, "config", "", lo.Must1(config.ConfigFile()), "Configuration file")
	flags.StringVarP(&rootOpts.profile, "profile", "p", "", "Profile to use")
	flags.StringVarP(&rootOpts.verbosity, "verbosity", "V", "info",
		fmt.Sprintf("Verbosity (%s)", strings.Join(levels, ", ")))
	flags.StringVarP(&rootOpts.privKey, "privkey", "", "", "Private key file")
	flags.StringSliceVarP(&rootOpts.pubKeys, "pubkeys", "", nil, "Public key file(s)")
	flags.StringVarP(&rootOpts.sandbox, "sandbox", "", "", "Sandbox backend")
}

func rootPreRun(_ *cobra.Command, _ []string) error {
	cfg, err := config.Read(rootOpts.configp)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rootOpts.config = cfg

	verbosity := rootOpts.verbosity
	if cfg.Verbosity != "" {
		verbosity = cfg.Verbosity
	}
	level, err := log.ParseLevel(verbosity)
	if err != nil {
		return err
	}
	log.SetLevel(level)

	if rootOpts.privKey == "" {
		rootOpts.privKey = cfg.PrivKey
	}

	if len(rootOpts.pubKeys) == 0 {
		rootOpts.pubKeys = cfg.PubKeys
	}

	backend, err := sandbox.Backend(rootOpts.sandbox)
	if err != nil {
		return err
	}

	switch backend {
	case sandbox.BubblewrapSandbox:
		rootOpts.Sandbox, err = sandbox.NewBubblewrap(&sandbox.BubblewrapOptions{
			ReadOnlyPaths: append([]string{
				rootOpts.configp,
				rootOpts.privKey,
			}, rootOpts.pubKeys...),
			ReadWritePaths:   nil,
			Tmpfs:            true,
			Devtmpfs:         true,
			Procfs:           true,
			AllowCommonPaths: true,
			Stdin:            io.Reader(nil),
			Stdout:           process.LogrusOutput,
			Stderr:           process.LogrusOutput,
		})
		if err != nil {
			return err
		}
	case sandbox.NoSandbox:
		rootOpts.Sandbox, err = sandbox.NewNoop()
		if err != nil {
			return err
		}
	}

	return nil
}
