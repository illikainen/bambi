package config

import (
	"os"
	"path/filepath"

	"github.com/illikainen/bambi/src/metadata"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

type Root struct {
	Settings
	Profiles map[string]Settings
}

type Settings struct {
	PrivKey   string
	PubKeys   []string
	Verbosity string
	URL       string
}

type Config struct {
	Root
	Path string
}

func Read(path string) (*Config, error) {
	log.Debugf("%s: reading config", path)

	c := &Config{Path: path}
	_, err := toml.DecodeFile(path, &c.Root)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func ConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, metadata.Name()), nil
}

func ConfigFile() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "config.toml"), nil
}
