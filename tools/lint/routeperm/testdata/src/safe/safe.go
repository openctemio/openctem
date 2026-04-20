package safe

// We simulate the real codebase by importing a local `middleware`
// package-shape with Require* helpers.
type middlewareShape struct{}

func (middlewareShape) Require(perm any) any         { return nil }
func (middlewareShape) RequireAny(perms ...any) any  { return nil }
func (middlewareShape) RequireTeamAdmin() any        { return nil }
func (middlewareShape) RequireCampaignRole(r any) any { return nil }

var middleware middlewareShape

type router struct{}

func (router) POST(path string, handler any, middlewares ...any)   {}
func (router) PUT(path string, handler any, middlewares ...any)    {}
func (router) PATCH(path string, handler any, middlewares ...any)  {}
func (router) DELETE(path string, handler any, middlewares ...any) {}

func register(r router, h any) {
	// Acceptable: inline Require.
	r.POST("/assets", h, middleware.Require("assets:write"))
	r.PUT("/assets/1", h, middleware.RequireAny("assets:write", "assets:admin"))
	r.PATCH("/tenant", h, middleware.RequireTeamAdmin())
	r.DELETE("/campaign/1", h, middleware.RequireCampaignRole("lead"))

	// Acceptable: public-by-design with opt-out comment.
	//routeperm:public — webhook receiver, HMAC-gated separately
	r.POST("/webhooks/incoming/jira", h)
}
