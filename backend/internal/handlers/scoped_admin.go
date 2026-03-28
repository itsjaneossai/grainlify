package handlers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/jagadeesh/grainlify/backend/internal/auth"
	"github.com/jagadeesh/grainlify/backend/internal/db"
)

// ScopedAdminHandler manages scoped (per-program / per-escrow) admin roles.
type ScopedAdminHandler struct {
	db *db.DB
}

func NewScopedAdminHandler(d *db.DB) *ScopedAdminHandler {
	return &ScopedAdminHandler{db: d}
}

type grantScopedAdminRequest struct {
	UserID    string `json:"user_id"`
	ScopeType string `json:"scope_type"` // "program" | "escrow"
	ScopeID   string `json:"scope_id"`
}

// GrantScopedAdmin grants a scoped admin role to a user for a specific program or escrow.
// Only global admins may call this endpoint.
//
// POST /admin/scoped-roles
func (h *ScopedAdminHandler) Grant() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}

		var req grantScopedAdminRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_json"})
		}

		targetUserID, err := uuid.Parse(strings.TrimSpace(req.UserID))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_user_id"})
		}

		scopeType := strings.TrimSpace(req.ScopeType)
		if scopeType != "program" && scopeType != "escrow" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_scope_type", "allowed": []string{"program", "escrow"}})
		}

		scopeID := strings.TrimSpace(req.ScopeID)
		if scopeID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "scope_id_required"})
		}

		granterSub, _ := c.Locals(auth.LocalUserID).(string)
		granterID, err := uuid.Parse(granterSub)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_user"})
		}

		_, err = h.db.Pool.Exec(c.Context(), `
INSERT INTO program_admins (user_id, scope_type, scope_id, granted_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, scope_type, scope_id) DO NOTHING
`, targetUserID, scopeType, scopeID, granterID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "grant_failed"})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	}
}

// RevokeScopedAdmin removes a scoped admin role from a user.
// Only global admins may call this endpoint.
//
// DELETE /admin/scoped-roles
func (h *ScopedAdminHandler) Revoke() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}

		var req grantScopedAdminRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_json"})
		}

		targetUserID, err := uuid.Parse(strings.TrimSpace(req.UserID))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_user_id"})
		}

		scopeType := strings.TrimSpace(req.ScopeType)
		if scopeType != "program" && scopeType != "escrow" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_scope_type"})
		}

		scopeID := strings.TrimSpace(req.ScopeID)
		if scopeID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "scope_id_required"})
		}

		ct, err := h.db.Pool.Exec(c.Context(), `
DELETE FROM program_admins
WHERE user_id = $1 AND scope_type = $2 AND scope_id = $3
`, targetUserID, scopeType, scopeID)
		if errors.Is(err, pgx.ErrNoRows) || ct.RowsAffected() == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "scoped_role_not_found"})
		}
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "revoke_failed"})
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	}
}

// ListScopedAdmins returns all scoped admin assignments, optionally filtered by scope_type and scope_id.
// Only global admins may call this endpoint.
//
// GET /admin/scoped-roles?scope_type=program&scope_id=<id>
func (h *ScopedAdminHandler) List() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if h.db == nil || h.db.Pool == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "db_not_configured"})
		}

		scopeType := strings.TrimSpace(c.Query("scope_type"))
		scopeID := strings.TrimSpace(c.Query("scope_id"))

		query := `
SELECT pa.id, pa.user_id, pa.scope_type, pa.scope_id, pa.granted_by, pa.created_at
FROM program_admins pa
WHERE ($1 = '' OR pa.scope_type = $1)
  AND ($2 = '' OR pa.scope_id   = $2)
ORDER BY pa.created_at DESC
LIMIT 100
`
		rows, err := h.db.Pool.Query(c.Context(), query, scopeType, scopeID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "list_failed"})
		}
		defer rows.Close()

		type row struct {
			ID        string `json:"id"`
			UserID    string `json:"user_id"`
			ScopeType string `json:"scope_type"`
			ScopeID   string `json:"scope_id"`
			GrantedBy string `json:"granted_by"`
			CreatedAt string `json:"created_at"`
		}

		var out []row
		for rows.Next() {
			var r row
			var id, userID, grantedBy uuid.UUID
			var createdAt interface{}
			if err := rows.Scan(&id, &userID, &r.ScopeType, &r.ScopeID, &grantedBy, &createdAt); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "list_failed"})
			}
			r.ID = id.String()
			r.UserID = userID.String()
			r.GrantedBy = grantedBy.String()
			if t, ok := createdAt.(interface{ String() string }); ok {
				r.CreatedAt = t.String()
			}
			out = append(out, r)
		}

		return c.Status(fiber.StatusOK).JSON(fiber.Map{"scoped_admins": out})
	}
}
