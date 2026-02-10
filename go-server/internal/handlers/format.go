package handlers

import (
	"github.com/jackc/pgx/v5/pgtype"
)

func formatTimestamp(ts pgtype.Timestamp) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.Format("2006-01-02T15:04:05Z")
}
