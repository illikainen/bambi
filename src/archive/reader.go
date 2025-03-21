package archive

import (
	"archive/tar"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/stringx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type ArchiveReader struct {
	path   string
	file   *os.File
	reader *tar.Reader
}

func Open(path string) (*ArchiveReader, error) {
	log.Tracef("%s: opening archive", path)

	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, err
	}

	return &ArchiveReader{
		path:   path,
		file:   f,
		reader: tar.NewReader(f),
	}, nil
}

func (r *ArchiveReader) Close() error {
	return r.file.Close()
}

// revive:disable-next-line
func (r *ArchiveReader) ExtractAll(basedir string) (err error) {
	basedir = filepath.Clean(basedir)

	entries, err := r.List()
	if err != nil {
		return err
	}

	for _, entry := range entries {
		dst, err := r.getExtractPath(basedir, entry.Path)
		if err != nil {
			return err
		}

		exists, err := iofs.Exists(dst)
		if err != nil {
			return err
		}

		if exists {
			return errors.Errorf("%s already exist", dst)
		}

		if entry.LinkPath != "" {
			linkDst, err := r.getLinkPath(basedir, dst, entry.LinkPath)
			if err != nil {
				return err
			}

			exists, err := iofs.Exists(linkDst)
			if err != nil {
				return err
			}

			if exists {
				return errors.Errorf("%s already exist", linkDst)
			}
		}
	}

	for {
		hdr, err := r.reader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		dst, err := r.getExtractPath(basedir, hdr.Name)
		if err != nil {
			return err
		}

		if hdr.Typeflag == tar.TypeSymlink {
			linkDst, err := r.getLinkPath(basedir, dst, hdr.Linkname)
			if err != nil {
				return err
			}
			log.Infof("extracting '%s' (symlink to '%s')", dst, linkDst)

			err = os.Symlink(linkDst, dst)
			if err != nil {
				return err
			}
		} else if hdr.Typeflag == tar.TypeReg {
			log.Infof("extracting '%s' (regular)", dst)

			err := os.MkdirAll(filepath.Dir(dst), 0700)
			if err != nil {
				return err
			}

			perm := fs.FileMode(0600)
			if hdr.Mode&0100 == 0100 {
				log.Tracef("setting executable bit on '%s'", dst)
				perm |= 0100
			}

			f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, perm) // #nosec G304
			if err != nil {
				return err
			}

			err = iofs.Copy(f, r.reader)
			if err != nil {
				return err
			}

			err = f.Close()
			if err != nil {
				return err
			}
		} else if hdr.Typeflag == tar.TypeDir {
			log.Infof("extracting '%s' (dir)", dst)

			err := os.MkdirAll(dst, 0700)
			if err != nil {
				return err
			}
		} else {
			return errors.Errorf("%s: unsupported file type", hdr.Name)
		}
	}

	return nil
}

func (r *ArchiveReader) getExtractPath(basedir string, name string) (string, error) {
	cleanName := filepath.Clean(name)
	if filepath.IsAbs(cleanName) {
		return "", errors.Errorf("%s: absolute path", cleanName)
	}

	path := filepath.Join(basedir, cleanName)

	// TODO: uncomment on Go >=1.20
	// if !filepath.IsLocal(path) {
	// 	return "", errors.Errorf("%s: not a local path", path)
	// }

	// filepath.Clean() (invoked by Join() and other functions) translates:
	//
	// ./foo//bar/baz/../dst to foo/bar/dst
	// . to .
	//
	// If basedir is a lone '.', we need to prepend it or the prefix
	// validation fail because it's stripped from the full path.
	if basedir == "." {
		path = "." + string(os.PathSeparator) + path
	}

	if !strings.HasPrefix(path, basedir+string(os.PathSeparator)) {
		return "", errors.Errorf("%s: invalid location", path)
	}

	if stringx.Sanitize(path) != path {
		return "", errors.Errorf("%s: invalid characters", path)
	}

	return path, nil
}

func (r *ArchiveReader) getLinkPath(basedir string, name string, linkname string) (string, error) {
	if filepath.IsAbs(filepath.Clean(linkname)) {
		return "", errors.Errorf("%s: absolute path", linkname)
	}

	// We don't use filepath.Join() here because it resolves '..'.  Note
	// that '..' is also resolved by filepath.Clean() which is validated
	// below.
	dir, _ := filepath.Split(name)
	path := dir + string(os.PathSeparator) + linkname

	// TODO: uncomment on Go >=1.20
	// if !filepath.IsLocal(filepath.Clean(path)) {
	// 	return "", errors.Errorf("%s: not a local path", path)
	// }

	prefix := ""
	if basedir == "." {
		prefix = "." + string(os.PathSeparator)
	}

	if !strings.HasPrefix(prefix+filepath.Clean(path), basedir+string(os.PathSeparator)) {
		return "", errors.Errorf("%s: invalid symlink target", path)
	}

	if stringx.Sanitize(path) != path {
		return "", errors.Errorf("%s: invalid symlink characters", path)
	}

	return linkname, nil
}

type Entry struct {
	Path     string
	LinkPath string
	Mode     string
}

func (r *ArchiveReader) List() ([]Entry, error) {
	entries := []Entry{}

	for {
		hdr, err := r.reader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		entries = append(entries, Entry{
			Path:     hdr.Name,
			LinkPath: hdr.Linkname,
			Mode:     hdr.FileInfo().Mode().String(),
		})
	}

	err := r.reset()
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func (r *ArchiveReader) reset() error {
	_, err := r.file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	r.reader = tar.NewReader(r.file)
	return nil
}
