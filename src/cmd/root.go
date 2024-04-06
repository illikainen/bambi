package cmd

import (
	"fmt"
	"strings"

	"github.com/illikainen/bambi/src/config"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-utils/src/flag"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootOpts struct {
	config   string
	logLevel string
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

	flag.PathVarP(
		flags,
		&rootOpts.config,
		"config",
		"",
		flag.Path{
			Value: lo.Must(config.ConfigFile()),
		},
		"Config file",
	)

	flags.StringVarP(
		&rootOpts.logLevel,
		"log-level",
		"",
		"info",
		fmt.Sprintf("Log level (%s)", strings.Join(levels, ", ")),
	)
}

func rootPreRun(_ *cobra.Command, _ []string) error {
	level, err := log.ParseLevel(rootOpts.logLevel)
	if err != nil {
		return err
	}
	log.SetLevel(level)

	return nil
}
