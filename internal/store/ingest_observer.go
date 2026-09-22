package store

import "github.com/networkshard/shardlure/pkg/models"

// Set before starting producers. The callback runs after a transaction returns,
// outside writeMu, and receives no event contents or identity labels.
func (s *Store) SetIngestObserver(fn func(models.Source, int, error)) {
	s.observerMu.Lock()
	s.ingestObserver = fn
	s.observerMu.Unlock()
}
func (s *Store) observeIngest(source models.Source, n int, err error) {
	s.observerMu.RLock()
	fn := s.ingestObserver
	s.observerMu.RUnlock()
	if fn != nil {
		if err != nil {
			n = 0
		}
		fn(source, n, err)
	}
}
