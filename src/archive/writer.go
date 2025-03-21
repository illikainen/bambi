package archive

import (
	"archive/tar"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type ArchiveWriter struct {
	path   string
	file   *os.File
	writer *tar.Writer
}

func Create(path string) (*ArchiveWriter, error) {
	log.Tracef("%s: creating archive", path)

	file, err := os.Create(path) // #nosec G304
	if err != nil {
		return nil, err
	}

	return &ArchiveWriter{
		path:   path,
		file:   file,
		writer: tar.NewWriter(file),
	}, nil
}

func (w *ArchiveWriter) Close() error {
	return errorx.Join(w.writer.Close(), w.file.Close())
}

func (w *ArchiveWriter) addFile(path string, info fs.FileInfo) (err error) {
	link := ""
	mode := info.Mode()

	if mode&os.ModeSymlink == os.ModeSymlink {
		link, err = os.Readlink(path)
		if err != nil {
			return err
		}
		log.Infof("adding '%s' (symlink to '%s')", path, link)
	} else if mode.IsRegular() {
		log.Infof("adding '%s' (regular)", path)
	} else if mode.IsDir() {
		log.Infof("adding '%s' (directory)", path)
	} else {
		return errors.Errorf("%s: unsupported file type", path)
	}

	hdr, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return err
	}

	name := filepath.Clean(path)
	if filepath.IsAbs(name) {
		name = strings.TrimLeft(name, string(os.PathSeparator))
	}
	hdr.Name = name

	err = w.writer.WriteHeader(hdr)
	if err != nil {
		return err
	}

	if mode.IsRegular() {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer errorx.Defer(f.Close, &err)
		return iofs.Copy(w.writer, f)
	}
	return nil
}

func (w *ArchiveWriter) AddAll(paths ...string) (err error) {
	for _, path := range paths {
		err = filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
			if err == nil {
				return w.addFile(path, info)
			}
			return err
		})
		if err != nil {
			return err
		}
	}

	return nil
}
