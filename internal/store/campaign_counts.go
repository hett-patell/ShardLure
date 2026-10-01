package store

import "context"

// CountCampaigns and CountScriptFamilies return the true row counts behind
// ListCampaigns and ListScriptFamilies, which are capped (200 by default,
// 1000 at most). The dashboard renders "showing N of M" from them so a capped
// list never reads as the whole. Both tables are bounded by distinct
// campaigns and script families, so a COUNT(*) is a cheap scan of the
// primary-key b-tree, not an events-sized read.
func (s *Store) CountCampaigns(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM campaigns`).Scan(&n)
	return n, err
}

func (s *Store) CountScriptFamilies(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM script_families`).Scan(&n)
	return n, err
}
