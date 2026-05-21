package store

func (s *Store) UpdateEventActor(id int64, actorID string) error {
	_, err := s.db.Exec(`UPDATE events SET actor_id=? WHERE id=?`, actorID, id)
	return err
}
