//go:build !linux

package safefile

import (
	"io/fs"
	"os"
)

type Root struct{}

func (*Root) CheckWritable() error { return ErrUnsupported }

func (*Root) Stat(string) (fs.FileInfo, error) { return nil, ErrUnsupported }

func (*Root) Info() (fs.FileInfo, error)            { return nil, ErrUnsupported }
func (*Root) Sync() error                           { return ErrUnsupported }
func (*Root) AvailableBytes() (uint64, error)       { return 0, ErrUnsupported }
func (*Root) OpenDirectory(string) (*Root, error)   { return nil, ErrUnsupported }
func (*Root) CreateDirectory(string) (*Root, error) { return nil, ErrUnsupported }

func (*Root) PublishNoReplace(string, string) error { return ErrUnsupported }

func (*Root) RemoveIfUnchanged(string, fs.FileInfo) error { return ErrUnsupported }

func (*Root) ReadNames(int) ([]string, error) { return nil, ErrUnsupported }

func SameFileState(fs.FileInfo, fs.FileInfo) bool { return false }

func EnsureDirectory(string) (*Root, error)           { return nil, ErrUnsupported }
func (*Root) RemoveCreated(string, fs.FileInfo) error { return ErrUnsupported }

func (*Root) CheckOutput() error { return ErrUnsupported }

func OpenRoot(string) (*Root, error)                                { return nil, ErrUnsupported }
func (*Root) OpenRegular(string) (*os.File, error)                  { return nil, ErrUnsupported }
func (*Root) CreateExclusive(string, fs.FileMode) (*os.File, error) { return nil, ErrUnsupported }
func (*Root) Close() error                                          { return nil }
func PublishNoReplace(string, string, string) error                 { return ErrUnsupported }
