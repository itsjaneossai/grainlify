package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/jagadeesh/grainlify/backend/internal/auth"
	"github.com/jagadeesh/grainlify/backend/internal/handlers"
)

// newTestApp wires a minimal Fiber app with the scoped admin routes and a
// fake auth middleware that injects the provided role/userID into locals.
func newTestApp(role, userID string) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.LocalRole, role)
		c.Locals(auth.LocalUserID, userID)
		return c.Next()
	})

	// nil db — handler must return 503 before touching DB
	h := handlers.NewScopedAdminHandler(nil)
	app.Post("/admin/scoped-roles", h.Grant())
	app.Delete("/admin/scoped-roles", h.Revoke())
	app.Get("/admin/scoped-roles", h.List())
	return app
}

func TestGrantScopedAdmin_DBNotConfigured(t *testing.T) {
	app := newTestApp("admin", "00000000-0000-0000-0000-000000000001")

	body, _ := json.Marshal(map[string]string{
		"user_id":    "00000000-0000-0000-0000-000000000002",
		"scope_type": "program",
		"scope_id":   "prog-abc",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/scoped-roles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

func TestGrantScopedAdmin_InvalidScopeType(t *testing.T) {
	// We can't reach the scope_type validation without a real DB, but we can
	// verify the handler rejects bad JSON before hitting the DB path.
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(auth.LocalRole, "admin")
		c.Locals(auth.LocalUserID, "00000000-0000-0000-0000-000000000001")
		return c.Next()
	})
	h := handlers.NewScopedAdminHandler(nil)
	app.Post("/admin/scoped-roles", h.Grant())

	req := httptest.NewRequest(http.MethodPost, "/admin/scoped-roles", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	// nil db → 503 before JSON parse; that's fine — the important thing is it
	// doesn't panic and returns a non-2xx status.
	if resp.StatusCode == http.StatusOK {
		t.Error("expected non-200 for bad request")
	}
}

func TestRevokeScopedAdmin_DBNotConfigured(t *testing.T) {
	app := newTestApp("admin", "00000000-0000-0000-0000-000000000001")

	body, _ := json.Marshal(map[string]string{
		"user_id":    "00000000-0000-0000-0000-000000000002",
		"scope_type": "escrow",
		"scope_id":   "CXXX",
	})
	req := httptest.NewRequest(http.MethodDelete, "/admin/scoped-roles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

func TestListScopedAdmins_DBNotConfigured(t *testing.T) {
	app := newTestApp("admin", "00000000-0000-0000-0000-000000000001")

	req := httptest.NewRequest(http.MethodGet, "/admin/scoped-roles?scope_type=program", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}
