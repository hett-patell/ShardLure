package store

func (s *Store) UpdateEventActor(id int64, actorID string) error {
	// Serialize with all other writers (SQLite single-writer); every other
	// public write method takes writeMu and this one must too.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return updateEventActor(s.db, id, actorID)
}

func updateEventActor(db sqlExecer, id int64, actorID string) error {
	_, err := db.Exec(`UPDATE events SET actor_id=? WHERE id=?`, actorID, id)
	return err
}
