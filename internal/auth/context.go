package auth

import "context"

// context key type to avoid collisions
type ctxKey string

const (
	ctxRole ctxKey = "pg_role"
	ctxSub  ctxKey = "pg_sub"
)

// WithRole stores the database role into context
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, ctxRole, role)
}

// RoleFromContext returns the database role stored in context, or empty string
func RoleFromContext(ctx context.Context) string {
	if v := ctx.Value(ctxRole); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WithSubject stores the user subject into context
func WithSubject(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, ctxSub, sub)
}

// SubjectFromContext gets the user subject from context
func SubjectFromContext(ctx context.Context) string {
	if v := ctx.Value(ctxSub); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
