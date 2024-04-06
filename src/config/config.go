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
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	path     string
	config   Root
	metadata toml.MetaData
}

type Keys struct {
	Sign map[string]struct {
		Public  []string
		Private string
	}
	Encrypt map[string]struct {
		Public  []string
		Private string
	}
}

type Root struct {
	Keys Keys
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

func (c *Config) ReadKeyrings() (*blob.Keyrings, error) {
	sign, err := c.readKeyring(cryptor.SignPurpose)
	if err != nil {
		return nil, err
	}
	if len(sign.NaCl.Private) == 0 && len(sign.RSA.Private) == 0 {
		return nil, errors.Wrap(cryptor.ErrMissingPrivateKey, "sign")
	}
	if len(sign.NaCl.Public) == 0 && len(sign.RSA.Public) == 0 {
		return nil, errors.Wrap(cryptor.ErrMissingPublicKey, "sign")
	}

	encrypt, err := c.readKeyring(cryptor.EncryptPurpose)
	if err != nil {
		return nil, err
	}
	if len(encrypt.NaCl.Private) == 0 && len(encrypt.RSA.Private) == 0 {
		return nil, errors.Wrap(cryptor.ErrMissingPrivateKey, "encrypt")
	}
	if len(encrypt.NaCl.Private) != 0 && len(encrypt.NaCl.Public) == 0 {
		return nil, errors.Wrap(cryptor.ErrMissingPublicKey, "NaCl encrypt")
	}
	if len(encrypt.RSA.Private) != 0 && len(encrypt.RSA.Public) == 0 {
		return nil, errors.Wrap(cryptor.ErrMissingPublicKey, "RSA encrypt")
	}
	if len(encrypt.NaCl.Public) > 0 && len(encrypt.RSA.Public) > 0 {
		if len(encrypt.NaCl.Private) == 0 || len(encrypt.RSA.Private) == 0 {
			return nil, errors.Wrap(cryptor.ErrMissingPrivateKey, "NaCl or RSA")
		}
		if len(encrypt.NaCl.Public) != len(encrypt.RSA.Public) {
			return nil, errors.Wrap(cryptor.ErrMissingPublicKey, "invalid encrypt config")
		}
	}

	return &blob.Keyrings{Sign: sign, Encrypt: encrypt}, nil
}

func (c *Config) readKeyring(purpose int) (*blob.Keyring, error) {
	naclPub, err := c.readPublicKeys("nacl", purpose)
	if err != nil {
		return nil, err
	}

	naclPriv, err := c.readPrivateKey("nacl", purpose)
	if err != nil {
		return nil, err
	}

	rsaPub, err := c.readPublicKeys("rsa", purpose)
	if err != nil {
		return nil, err
	}

	rsaPriv, err := c.readPrivateKey("rsa", purpose)
	if err != nil {
		return nil, err
	}

	return &blob.Keyring{
		NaCl: blob.Keys{
			Public:  naclPub,
			Private: naclPriv,
		},
		RSA: blob.Keys{
			Public:  rsaPub,
			Private: rsaPriv,
		},
	}, nil
}

func (c *Config) readPublicKeys(kind string, purpose int) ([]cryptor.PublicKey, error) {
	paths := []string{}
	if purpose == cryptor.SignPurpose {
		paths = append(paths, c.config.Keys.Sign[kind].Public...)
	} else if purpose == cryptor.EncryptPurpose {
		paths = append(paths, c.config.Keys.Encrypt[kind].Public...)
	} else {
		return nil, cryptor.ErrInvalidPurpose
	}

	pubKeys := []cryptor.PublicKey{}
	for _, path := range paths {
		realPath, err := expand(path)
		if err != nil {
			return nil, err
		}

		pubKey, err := asymmetric.ReadPublicKey(cryptor.AsymmetricMap[kind], realPath, purpose)
		if err != nil {
			return nil, err
		}
		pubKeys = append(pubKeys, pubKey)
	}

	return pubKeys, nil
}

func (c *Config) readPrivateKey(kind string, purpose int) ([]cryptor.PrivateKey, error) {
	path := ""
	if purpose == cryptor.SignPurpose {
		path = c.config.Keys.Sign[kind].Private
	} else if purpose == cryptor.EncryptPurpose {
		path = c.config.Keys.Encrypt[kind].Private
	} else {
		return nil, cryptor.ErrInvalidPurpose
	}

	if path == "" {
		return nil, nil
	}

	realPath, err := expand(path)
	if err != nil {
		return nil, err
	}

	privKey, err := asymmetric.ReadPrivateKey(cryptor.AsymmetricMap[kind], realPath, purpose)
	if err != nil {
		return nil, err
	}
	return []cryptor.PrivateKey{privKey}, nil
}

func (c *Config) SandboxPaths() (ro []string, rw []string, err error) {
	ro = append(ro, c.path)

	keyPaths := []string{}
	keyPaths = append(keyPaths, c.config.Keys.Sign["nacl"].Public...)
	keyPaths = append(keyPaths, c.config.Keys.Sign["nacl"].Private)
	keyPaths = append(keyPaths, c.config.Keys.Sign["rsa"].Public...)
	keyPaths = append(keyPaths, c.config.Keys.Sign["rsa"].Private)
	keyPaths = append(keyPaths, c.config.Keys.Encrypt["nacl"].Public...)
	keyPaths = append(keyPaths, c.config.Keys.Encrypt["nacl"].Private)
	keyPaths = append(keyPaths, c.config.Keys.Encrypt["rsa"].Public...)
	keyPaths = append(keyPaths, c.config.Keys.Encrypt["rsa"].Private)

	for _, path := range keyPaths {
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
