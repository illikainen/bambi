package archive

import (
	"archive/zip"
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
	writer *zip.Writer
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
		writer: zip.NewWriter(file),
	}, nil
}

func (a *ArchiveWriter) Close() error {
	return errorx.Join(a.writer.Close(), a.file.Close())
}

func (a *ArchiveWriter) AddFile(path string) error {
	name := filepath.Clean(path)

	// FIXME: File names must be relative but this is insufficient (e.g.,
	// C:).  This doesn't affect us from a security point of view because
	// we validate file names during the extraction.  However, it will
	// probably break Windows environments.
	if filepath.IsAbs(name) {
		name = strings.TrimLeft(name, string(os.PathSeparator))
	}

	// ZIP paths are separated by forward slashes.
	name = strings.ReplaceAll(name, string(os.PathSeparator), "/")

	log.Infof("adding: %s", path)

	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	hdr := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	hdr.SetMode(stat.Mode().Perm())

	outf, err := a.writer.CreateHeader(hdr)
	if err != nil {
		return err
	}
	return iofs.Copy(outf, path)
}

func (a *ArchiveWriter) AddAll(paths ...string) (err error) {
	for _, path := range paths {
		err = filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				if err == filepath.SkipDir {
					return errors.Errorf("unknown error")
				}
				return err
			}

			if !info.IsDir() {
				return a.AddFile(path)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

type ArchiveReader struct {
	path   string
	file   *os.File
	reader *zip.Reader
}

func Open(path string) (*ArchiveReader, error) {
	log.Tracef("%s: opening archive", path)

	file, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, err
	}

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(file, stat.Size())
	if err != nil {
		return nil, err
	}

	return &ArchiveReader{
		path:   path,
		file:   file,
		reader: reader,
	}, nil
}

func (a *ArchiveReader) Close() error {
	return a.file.Close()
}

func (a *ArchiveReader) ExtractAll(path string) (err error) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	for _, file := range a.reader.File {
		name := strings.ReplaceAll(file.Name, "/", string(os.PathSeparator))

		dst := filepath.Join(path, name)
		dstAbs, err := filepath.Abs(dst)
		if err != nil {
			return err
		}

		if !strings.HasPrefix(dstAbs, pathAbs+string(os.PathSeparator)) {
			return errors.Errorf("%s: invalid name", file.Name)
		}

		log.Infof("extracting: %s", dst)

		dir, _ := filepath.Split(dst)
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}

		dstf, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, file.Mode().Perm()) // #nosec G304
		if err != nil {
			return err
		}

		err = iofs.Copy(dstf, file)
		if err != nil {
			return err
		}
	}

	return nil
}
