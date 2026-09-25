package backup

import "errors"

var (
	ErrInvalidManifest   = errors.New("backup: invalid manifest or content")
	ErrManifestLimit     = errors.New("backup: manifest resource limit exceeded")
	ErrDestinationExists = errors.New("backup: destination already exists")
	ErrUnsafePath        = errors.New("backup: unsafe or overlapping path")
	ErrIncomplete        = errors.New("backup: incomplete operation")
	ErrInsufficientSpace = errors.New("backup: insufficient free space")
	ErrSourceChanged     = errors.New("backup: source missing or changed")
	ErrConfiguration     = errors.New("backup: invalid or missing configuration")
	ErrIO                = errors.New("backup: filesystem or database operation failed")
)

// Failure renders only a fixed category. Only explicit CLI output may show the
// operator-owned staging path; logs and HTTP errors must not print that path.
type Failure struct {
	Kind    error
	Staging string
	cause   error
}

func (e *Failure) Error() string        { return e.Kind.Error() }
func (e *Failure) Unwrap() error        { return e.cause }
func (e *Failure) Is(target error) bool { return target == e.Kind }
func failure(kind, cause error, stage string) error {
	return &Failure{Kind: kind, Staging: stage, cause: cause}
}
