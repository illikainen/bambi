package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/illikainen/bambi/src/config"
	"github.com/illikainen/bambi/src/metadata"
	"github.com/illikainen/bambi/src/sandbox"

	"github.com/illikainen/go-utils/src/flag"
	"github.com/illikainen/go-utils/src/logging"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootOpts struct {
	configp   flag.Path
	config    *config.Config
	profile   string
	verbosity logging.LogLevel
	privKey   flag.Path
	pubKeys   flag.PathSlice
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

	rootOpts.configp.State = flag.MustExist
	flags.Var(&rootOpts.configp, "config", "Configuration file")
	flags.StringVarP(&rootOpts.profile, "profile", "p", "", "Profile to use")
	flags.Var(&rootOpts.verbosity, "verbosity", fmt.Sprintf("Verbosity (%s)", strings.Join(levels, ", ")))
	flags.Var(&rootOpts.privKey, "privkey", "Private key file")
	lo.Must0(flags.MarkHidden("privkey"))
	flags.Var(&rootOpts.pubKeys, "pubkeys", "Public key file(s)")
	lo.Must0(flags.MarkHidden("pubkeys"))
}

func rootPreRun(cmd *cobra.Command, _ []string) error {
	cfgPath, err := config.ConfigFile()
	if err != nil {
		return err
	}

	flags := cmd.Flags()
	if err := flag.SetFallback(flags, "config", cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	rootOpts.config, err = config.Read(rootOpts.configp.Value)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if rootOpts.config != nil {
		cfg := rootOpts.config
		pcfg := cfg.Profiles[rootOpts.profile]

		if err := flag.SetFallback(flags, "verbosity", pcfg.Verbosity, cfg.Verbosity); err != nil {
			return err
		}
		if err := flag.SetFallback(flags, "privkey", pcfg.PrivKey, cfg.PrivKey); err != nil {
			return err
		}
		if err := flag.SetFallback(flags, "pubkeys", pcfg.PubKeys, cfg.PubKeys); err != nil {
			return err
		}
	}

	return sandbox.Exec(cmd.CalledAs(), flags)
}
