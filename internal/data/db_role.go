package data

import (
	"context"
	"strings"

	"github.com/CrunchyData/pg_featureserv/internal/auth"
	"github.com/jackc/pgx/v4/pgxpool"
)

// withRoleConn acquires a pooled connection, sets ROLE if present in context,
// executes fn, and then resets ROLE and releases the connection.
func withRoleConn(ctx context.Context, db *pgxpool.Pool, fn func(*pgxpool.Conn) error) error {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	role := auth.RoleFromContext(ctx)
	if role != "" {
		q := quoteIdent(role)
		if _, err := conn.Exec(ctx, "SET ROLE "+q); err != nil {
			return err
		}
		defer conn.Exec(ctx, "RESET ROLE") //nolint:errcheck
	}
	return fn(conn)
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
