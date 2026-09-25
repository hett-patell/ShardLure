package backup

import (
	"errors"

	"github.com/networkshard/shardlure/internal/store"
)

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

// pathFreeReasons are fixed store sentinels that name the fix without naming a
// path, so Error may append them to the category.
var pathFreeReasons = []error{store.ErrDatabaseUnsafe, store.ErrDatabaseOwner, store.ErrDatabaseAccess, store.ErrDatabaseUnsupported}

func (e *Failure) Error() string {
	for _, reason := range pathFreeReasons {
		if errors.Is(e.cause, reason) {
			return e.Kind.Error() + ": " + reason.Error()
		}
	}
	return e.Kind.Error()
}
func (e *Failure) Unwrap() error        { return e.cause }
func (e *Failure) Is(target error) bool { return target == e.Kind }
func failure(kind, cause error, stage string) error {
	return &Failure{Kind: kind, Staging: stage, cause: cause}
}
