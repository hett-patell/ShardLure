package store

func (s *Store) UpdateEventActor(id int64, actorID string) error {
	return updateEventActor(s.db, id, actorID)
}

func updateEventActor(db sqlExecer, id int64, actorID string) error {
	_, err := db.Exec(`UPDATE events SET actor_id=? WHERE id=?`, actorID, id)
	return err
}
