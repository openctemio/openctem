package flagged

// Stand-in shapes so the package type-checks without importing the
// real codebase.

type router struct{}

func (router) POST(path string, handler any, middlewares ...any)   {}
func (router) PUT(path string, handler any, middlewares ...any)    {}
func (router) PATCH(path string, handler any, middlewares ...any)  {}
func (router) DELETE(path string, handler any, middlewares ...any) {}
func (router) GET(path string, handler any, middlewares ...any)    {}

func register(r router, h any) {
	r.POST("/widgets", h) // want `POST registered without middleware.Require`
	r.PUT("/widgets/1", h) // want `PUT registered without middleware.Require`
	r.PATCH("/widgets/1", h) // want `PATCH registered without middleware.Require`
	r.DELETE("/widgets/1", h) // want `DELETE registered without middleware.Require`
	// GET is not a write; must NOT be flagged.
	r.GET("/widgets", h)
}
