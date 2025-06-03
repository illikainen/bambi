package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/illikainen/bambi/src/config"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootOpts struct {
	config.Config
	config  string
	Sandbox sandbox.Sandbox
	sandbox string
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

	flags.StringVarP(&rootOpts.config, "config", "", lo.Must1(config.ConfigFile()), "Configuration file")
	flags.StringVarP(&rootOpts.Profile, "profile", "p", "", "Profile to use")
	flags.StringVarP(&rootOpts.Verbosity, "verbosity", "V", "",
		fmt.Sprintf("Verbosity (%s)", strings.Join(levels, ", ")))
	flags.StringVarP(&rootOpts.PrivKey, "privkey", "", "", "Private key file")
	flags.StringSliceVarP(&rootOpts.PubKeys, "pubkeys", "", nil, "Public key file(s)")
	flags.StringVarP(&rootOpts.sandbox, "sandbox", "", "", "Sandbox backend")
}

func rootPreRun(_ *cobra.Command, _ []string) error {
	cfg, err := config.Read(rootOpts.config, &rootOpts.Config)
	if err != nil {
		return err
	}
	rootOpts.Config = *cfg

	level, err := log.ParseLevel(rootOpts.Verbosity)
	if err != nil {
		return err
	}
	log.SetLevel(level)

	name := lo.Ternary(rootOpts.sandbox != "", rootOpts.sandbox, rootOpts.Config.Sandbox)
	backend, err := sandbox.Backend(name)
	if err != nil {
		return err
	}

	switch backend {
	case sandbox.BubblewrapSandbox:
		rootOpts.Sandbox, err = sandbox.NewBubblewrap(&sandbox.BubblewrapOptions{
			ReadOnlyPaths: append([]string{
				rootOpts.config,
				rootOpts.PrivKey,
			}, rootOpts.PubKeys...),
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
