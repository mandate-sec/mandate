package db

// AdminCredentials reads the password hash and session generation from one snapshot.
func (d *DB) AdminCredentials() (hash, generation string, err error) {
	err = d.QueryRow(`SELECT
		COALESCE((SELECT value FROM settings WHERE key='auth.password_hash'), ''),
		COALESCE((SELECT value FROM settings WHERE key='auth.session_generation'), '')`).Scan(&hash, &generation)
	return
}

// ChangeAdminPassword revokes prior sessions in the same statement as the password change.
func (d *DB) ChangeAdminPassword(oldHash, newHash, generation string) (bool, error) {
	result, err := d.Exec(`WITH changed AS (
		UPDATE settings SET value=$2, updated_at=now()
		WHERE key='auth.password_hash' AND value=$1 RETURNING 1
	)
	INSERT INTO settings(key,value) SELECT 'auth.session_generation', $3 FROM changed
	ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, oldHash, newHash, generation)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}
