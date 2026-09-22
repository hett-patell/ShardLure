//go:build !linux

package safefile

import (
	"io/fs"
	"os"
)

type Root struct{}

func (*Root) CheckOutput() error { return ErrUnsupported }

func OpenRoot(string) (*Root, error)                                { return nil, ErrUnsupported }
func (*Root) OpenRegular(string) (*os.File, error)                  { return nil, ErrUnsupported }
func (*Root) CreateExclusive(string, fs.FileMode) (*os.File, error) { return nil, ErrUnsupported }
func (*Root) Close() error                                          { return nil }
func PublishNoReplace(string, string, string) error                 { return ErrUnsupported }
