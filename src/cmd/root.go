package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/illikainen/bambi/src/config"
	"github.com/illikainen/bambi/src/metadata"

	"github.com/illikainen/go-netutils/src/sshx"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/flag"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/logging"
	"github.com/illikainen/go-utils/src/process"
	"github.com/illikainen/go-utils/src/sandbox"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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

	flags.Var(&rootOpts.configp, "config", "Configuration file")
	flags.StringVarP(&rootOpts.profile, "profile", "p", "", "Profile to use")
	flags.Var(&rootOpts.verbosity, "verbosity", fmt.Sprintf("Verbosity (%s)", strings.Join(levels, ", ")))
	flags.Var(&rootOpts.privKey, "privkey", "Private key file")
	flags.Var(&rootOpts.pubKeys, "pubkeys", "Public key file(s)")
}

func rootPreRun(cmd *cobra.Command, _ []string) error {
	cfgPath, err := config.ConfigFile()
	if err != nil {
		return err
	}

	flags := cmd.Flags()
	if err := flag.SetFallback(flags, "config", cfgPath); err != nil {
		return err
	}

	rootOpts.config, err = config.Read(rootOpts.configp.Value)
	if err != nil {
		return err
	}

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

	if sandbox.Compatible() && !sandbox.IsSandboxed() {
		paths := []*flag.Path{}
		flags.VisitAll(func(f *pflag.Flag) {
			switch v := f.Value.(type) {
			case *flag.Path:
				paths = append(paths, v)
			case *flag.PathSlice:
				paths = append(paths, v.Value...)
			case *flag.URL:
				if v.Value.Scheme == "file" {
					path := &flag.Path{Value: v.Value.Path}
					if cmd.CalledAs() == "put" {
						path.Mode = flag.ReadWriteMode
					}
					paths = append(paths, path)
				}
			}
		})

		ro := []string{}
		rw := []string{}
		created := []string{}
		for _, path := range paths {
			if path.String() == "" {
				continue
			}

			if path.Mode == flag.ReadWriteMode {
				newPaths, err := ensurePath(path)
				if err != nil {
					return err
				}

				created = append(created, newPaths...)
				rw = append(rw, created...)
			} else {
				if len(path.Values) <= 0 {
					ro = append(ro, path.Value)
				} else {
					ro = append(ro, path.Values...)
				}
			}
		}

		share := 0
		if cmd.CalledAs() == "get" || cmd.CalledAs() == "put" {
			share |= sandbox.ShareNet

			sshRO, sshRW, err := sshx.SandboxPaths()
			if err != nil {
				return err
			}
			ro = append(ro, sshRO...)
			rw = append(rw, sshRW...)
		}

		_, err = sandbox.Exec(sandbox.Options{
			Command: os.Args,
			RO:      ro,
			RW:      rw,
			Share:   share,
			Stdout:  process.LogrusOutput,
			Stderr:  process.LogrusOutput,
		})
		if err != nil {
			errs := []error{err}
			for _, path := range created {
				log.Debugf("removing %s", path)
				errs = append(errs, iofs.Remove(path))
			}
			return errorx.Join(errs...)
		}
		os.Exit(0)
	}
	return nil
}

func ensurePath(path *flag.Path) ([]string, error) {
	paths := path.Values
	if len(paths) <= 0 {
		paths = append(paths, path.Value)
	}

	created := []string{}
	for _, p := range paths {
		if p == "" {
			continue
		}

		exists, err := iofs.Exists(p)
		if err != nil {
			return created, err
		}
		if exists {
			return created, nil
		}

		if path.State&flag.MustBeDir == flag.MustBeDir {
			dir := p
			parts := strings.Split(p, string(os.PathSeparator))

			for i := len(parts); i > 0; i-- {
				cur := strings.Join(parts[:i], string(os.PathSeparator))
				exists, err := iofs.Exists(cur)
				if err != nil {
					return created, err
				}
				if exists {
					break
				}
				dir = cur
			}

			log.Debugf("creating %s as a directory", p)
			err := os.MkdirAll(p, 0700)
			if err != nil {
				return created, err
			}

			created = append(created, dir)
		} else {
			log.Debugf("creating %s as a regular file", p)
			f, err := os.Create(p) // #nosec G304
			if err != nil {
				return created, err
			}

			created = append(created, p)

			err = f.Close()
			if err != nil {
				return created, err
			}
		}
	}

	return created, nil
}
