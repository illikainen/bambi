package config

import (
	"os"
	"path/filepath"

	"github.com/illikainen/bambi/src/metadata"

	"github.com/BurntSushi/toml"
	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/stringx"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	path     string
	config   Root
	metadata toml.MetaData
}

type Root struct {
	PubKeys []string
	PrivKey string
}

func Read(path string) (*Config, error) {
	log.Debugf("%s: reading config", path)

	config := Root{}
	meta, err := toml.DecodeFile(path, &config)
	if err != nil {
		return nil, err
	}

	return &Config{path: path, config: config, metadata: meta}, nil
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

func (c *Config) ReadKeyring() (*blob.Keyring, error) {
	pubKeys := []cryptor.PublicKey{}

	for _, pubFile := range c.config.PubKeys {
		path, err := expand(pubFile)
		if err != nil {
			return nil, err
		}

		pubKey, err := asymmetric.ReadPublicKey(path)
		if err != nil {
			return nil, err
		}

		pubKeys = append(pubKeys, pubKey)
	}

	path, err := expand(c.config.PrivKey)
	if err != nil {
		return nil, err
	}

	privKey, err := asymmetric.ReadPrivateKey(path)
	if err != nil {
		return nil, err
	}

	return &blob.Keyring{Public: pubKeys, Private: privKey}, nil
}

func (c *Config) SandboxPaths() (ro []string, rw []string, err error) {
	roOrig := []string{c.path, c.config.PrivKey}
	roOrig = append(roOrig, c.config.PubKeys...)

	for _, path := range roOrig {
		realPath, err := expand(path)
		if err != nil {
			return nil, nil, err
		}

		ro = append(ro, realPath)
	}

	return ro, nil, err
}

func expand(path string) (string, error) {
	intPath, err := stringx.Interpolate(path)
	if err != nil {
		return "", err
	}

	realPath, err := iofs.Expand(intPath)
	if err != nil {
		return "", err
	}

	return realPath, nil
}
