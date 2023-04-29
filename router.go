// Package httprouter是一个基于 trie树的高性能 HTTP 请求路由器。
// 一个简单的例子：
//
//	package main
//
//	import (
//	    "fmt"
//	    "github.com/julienschmidt/httprouter"
//	    "net/http"
//	    "log"
//	)
//
//	func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
//	    fmt.Fprint(w, "Welcome!\n")
//	}
//
//	func Hello(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
//	    fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
//	}
//
//	func main() {
//	    router := httprouter.New()
//	    router.GET("/", Index)
//	    router.GET("/hello/:name", Hello)
//
//	    log.Fatal(http.ListenAndServe(":8080", router))
//	}
//
// 路由器通过请求方法和路径来匹配传入的请求
// 如果已经为该路径和请求方法注册了一个处理函数，路由器就将请求委托给该函数进行处理
//
// 对于 GET、POST、PUT、PATCH、DELETE 和 OPTIONS 方法，存在快捷函数来注册处理函数
// 对于所有其他方法，可以使用 router.Handle 函数来注册处理函数。
//
// 注册的路径，用于路由器匹配传入的请求，可以包含两种类型的参数：
//
//	语法    类型
//	:name     命名参数
//	*name     捕获所有参数
//
// 命名参数是动态路径段。它们匹配任何东西，直到下一个'/'或路径结束：
//
//	路径: /blog/:category/:post
//
//
//	请求:
//	 /blog/go/request-routers            match: category="go", post="request-routers"
//	 /blog/go/request-routers/           no match, but the router would redirect
//	 /blog/go/                           no match
//	 /blog/go/request-routers/comments   no match
//
// Catch-all parameters match anything until the path end, including the
// directory index (the '/' before the catch-all). Since they match anything
// until the end, catch-all parameters must always be the final path element.
//
//	Path: /files/*filepath
//
//	Requests:
//	 /files/                             match: filepath="/"
//	 /files/LICENSE                      match: filepath="/LICENSE"
//	 /files/templates/article.html       match: filepath="/templates/article.html"
//	 /files                              no match, but the router would redirect
//
// The value of parameters is saved as a slice of the Param struct, consisting
// each of a key and a value. The slice is passed to the Handle func as a third
// parameter.
// There are two ways to retrieve the value of a parameter:
//
//	// by the name of the parameter
//	user := ps.ByName("user") // defined by :user or *user
//
//	// by the index of the parameter. This way you can also get the name (key)
//	thirdKey   := ps[2].Key   // the name of the 3rd parameter
//	thirdValue := ps[2].Value // the value of the 3rd parameter
package httprouter

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

// Handle 这段代码定义了一个 Handle 类型，它是一个函数类型，可以用来注册路由来处理 HTTP 请求。
// 这个类型的函数与 http.HandlerFunc 类似，都接受一个 http.ResponseWriter 和一个 *http.Request 参数，用于处理 HTTP 请求和响应。
// 不同的是，Handle 类型函数还有一个 Params 参数，用于保存路由匹配的通配符（路径变量）的值。
type Handle func(http.ResponseWriter, *http.Request, Params)

// Param 是一个结构体类型，它包含了两个字段：Key 和 Value
// Key 表示 URL 参数的键，Value 表示 URL 参数的值
// 在路由处理器中，可以使用 Params 类型来保存多个 Param，其中 Params 类型实际上是 Param 结构体的切片。
type Param struct {
	Key   string
	Value string
}

// Params 这段代码定义了一个类型 Params, 它是一个包含多个 Param 的切片类型.
// The slice is ordered, the first URL parameter is also the first slice value.
// It is therefore safe to read values by the index.
// 每个 Param 包含一个通配符名称和对应的值。因此，Handle 函数可以使用 Params 参数来访问路由匹配的通配符（路径变量）的值，从而进行更复杂的路由处理。
//
// Params 值是一个包含多个 Param 结构体的切片, 每个 Param 结构体包含一个通配符名称和对应的值.
// 它的具体样子取决于具体的应用程序和路由规则.
// 例如, 如果路由规则是 /blog/:category/:post, 那么 Params 的值可能是:
//
//	[]Param{
//		{Key: "category", Value: "go"},
//		{Key: "post", Value: "request-routers"},
//	}
//
// 如果路由规则是 /files/*filepath, 那么 Params 的值可能是:
//
//	[]Param{
//		{Key: "filepath", Value: "/home/user/"},
//	}
//
// 如果路由规则是 /user/:name/*, 那么 Params 的值可能是:
//
//	[]Param{
//		{Key: "name", Value: "gopher"},
//		{Key: "wildcard", Value: "/a/b/c"},
//	}
//
// 如果路由规则是 /user/:name/*filepath, 那么 Params 的值可能是:
//
//	[]Param{
//		{Key: "name", Value: "gopher"},
//		{Key: "filepath", Value: "/a/b/c"},
//	}
type Params []Param

// ByName 这是一个名为 ByName 的方法, 它是在 Params 类型上定义的.
// 它接受一个字符串类型的参数 name, 代表要查找的 Params 中的 Param 的键.
// 方法首先迭代 Params 切片中的每个元素（即每个 Param）, 并检查它们的键是否与提供的 name 相匹配.
// 如果找到匹配的 Param，则返回它的值, 否则，方法返回一个空字符串.
// 这个方法可以用来从路由的 Params 中检索特定的值.
func (ps Params) ByName(name string) string {
	for _, p := range ps {
		if p.Key == name {
			return p.Value
		}
	}
	return ""
}

// 这段代码定义了一个 paramsKey 结构体类型, 用来作为上下文中 URL 参数存储的键值
type paramsKey struct{}

// ParamsKey 这段代码声明了一个 ParamsKey 变量，其类型为 paramsKey, 它是一个结构体类型.
// 并用其初始化一个新的 paramsKey 实例, 用来作为上下文中 URL 参数存储的键值.
// 这样就得到了一个独一无二的键值, 可以用来存储和访问请求上下文中的 URL 参数.
// 这种方式可以保证不同的上下文使用不同的键，避免了键名冲突的问题。
// 在处理请求时，可以使用 ParamsKey 变量来获取请求上下文中的 URL 参数。
var ParamsKey = paramsKey{}

// ParamsFromContext 该函数的目的是在请求处理函数中方便地获取请求的URL参数，从而进行更复杂的请求处理。
// 这段代码定义了一个名为ParamsFromContext的函数，用于从请求的上下文中提取URL参数。
// 函数的参数是context.Context类型，函数返回值是Params类型。
func ParamsFromContext(ctx context.Context) Params {
	// 使用Value方法从请求上下文中获取ParamsKey对应的值，即请求的URL参数。
	// 如果值存在并且类型是Params，则将其转换为Params类型并返回。
	// 如果不存在或者类型不匹配，则返回空的Params值。
	p, _ := ctx.Value(ParamsKey).(Params)
	return p
}

// MatchedRoutePathParam 这段代码定义了一个名为 MatchedRoutePathParam 的变量，用于存储匹配到的路由的路径参数。
// 如果 Router.SaveMatchedRoutePath 设置为 true，则该参数名和对应的路径将被存储在请求上下文中，并可以通过该参数名从请求上下文中获取路径参数值。
// 通常情况下，该参数被用于记录当前匹配到的路由的路径，以便在处理请求时进行参考或记录。
var MatchedRoutePathParam = "$matchedRoutePath"

// MatchedRoutePath retrieves the path of the matched route.
// Router.SaveMatchedRoutePath must have been enabled when the respective handler was added
// MatchedRoutePath 方法用于获取匹配到的路由的路径。
// 如果在添加路由处理函数时启用了 Router.SaveMatchedRoutePath，它返回匹配到的路由的路径，否则返回一个空字符串。
// 在该方法中，首先调用 ByName 方法获取名为 $matchedRoutePath 的 Param 对象的值
// 因为在添加处理函数时，如果启用了 Router.SaveMatchedRoutePath，那么就会把匹配到的路由路径值作为 $matchedRoutePath 的值保存到 Params 中
// 所以，调用 ByName 方法可以返回这个值，即为匹配到的路由的路径。
func (ps Params) MatchedRoutePath() string {
	return ps.ByName(MatchedRoutePathParam)
}

// Router 是一个 HTTP 请求路由器，实现了 http.Handler 接口
// 通过可配置的路由，可以将请求分发给不同的处理函数
type Router struct {
	// 存储所有路由树的 map
	// key 是请求方法，value 是路由树
	// 每棵路由树都是一个前缀树，对应一个 HTTP方法，其中包含了该方法下所有的路由信息
	trees map[string]*node

	// 一个同步池，用于减少参数解析器的分配和垃圾回收的负担
	paramsPool sync.Pool
	// 路由路径中参数的最大数量，默认为 65535
	// 超过这个数量的参数将导致路由器返回错误响应
	maxParams uint16

	// If enabled, adds the matched route path onto the http.Request context
	// before invoking the handler.
	// The matched route path is only added to handlers of routes that were
	// registered when this option was enabled.
	// 如果启用，则将匹配的路由路径添加到请求上下文中
	SaveMatchedRoutePath bool

	// Enables automatic redirection if the current route can't be matched but a
	// handler for the path with (without) the trailing slash exists.
	// For example if /foo/ is requested but a route only exists for /foo, the
	// client is redirected to /foo with http status code 301 for GET requests
	// and 308 for all other request methods.
	// 如果启用，将自动重定向到没有尾部斜杠的路由路径
	RedirectTrailingSlash bool

	// If enabled, the router tries to fix the current request path, if no
	// handle is registered for it.
	// First superfluous path elements like ../ or // are removed.
	// Afterwards the router does a case-insensitive lookup of the cleaned path.
	// If a handle can be found for this route, the router makes a redirection
	// to the corrected path with status code 301 for GET requests and 308 for
	// all other request methods.
	// For example /FOO and /..//Foo could be redirected to /foo.
	// RedirectTrailingSlash is independent of this option.
	// 如果启用，则会自动修复请求的路径，并将请求重定向到修复后的路径。
	RedirectFixedPath bool

	// If enabled, the router checks if another method is allowed for the
	// current route, if the current request can not be routed.
	// If this is the case, the request is answered with 'Method Not Allowed'
	// and HTTP status code 405.
	// If no other Method is allowed, the request is delegated to the NotFound
	// handler.
	// 如果启用，则当找不到与请求方法匹配的路由时，检查是否允许其他请求方法，如果允许则返回 HTTP 状态码 405，否则将请求委派给 NotFound 处理程序。
	HandleMethodNotAllowed bool

	// If enabled, the router automatically replies to OPTIONS requests.
	// Custom OPTIONS handlers take priority over automatic replies.
	// 如果启用，将自动回复 OPTIONS 请求。自定义 OPTIONS 处理程序优先于自动回复。
	HandleOPTIONS bool

	// An optional http.Handler that is called on automatic OPTIONS requests.
	// The handler is only called if HandleOPTIONS is true and no OPTIONS
	// handler for the specific path was set.
	// The "Allowed" header is set before calling the handler.
	// 一个可选的 http.Handler，在自动 OPTIONS 请求时调用
	// 只有在 HandleOPTIONS 为 true 且未设置特定路径的 OPTIONS 处理程序时才调用该处理程序。
	GlobalOPTIONS http.Handler

	// Cached value of global (*) allowed methods
	// 全局 (*) 允许的方法的缓存值。
	globalAllowed string

	// Configurable http.Handler which is called when no matching route is
	// found. If it is not set, http.NotFound is used.
	// 当找不到与请求路径匹配的路由时调用的处理程序。
	NotFound http.Handler

	// Configurable http.Handler which is called when a request
	// cannot be routed and HandleMethodNotAllowed is true.
	// If it is not set, http.Error with http.StatusMethodNotAllowed is used.
	// The "Allow" header with allowed request methods is set before the handler
	// is called.
	// 当找不到与请求方法匹配的路由时调用的处理程序。如果未设置，则使用 http.Error 和 http.StatusMethodNotAllowed。
	MethodNotAllowed http.Handler

	// Function to handle panics recovered from http handlers.
	// It should be used to generate a error page and return the http error code
	// 500 (Internal Server Error).
	// The handler can be used to keep your server from crashing because of
	// unrecovered panics.
	// 用于处理从 HTTP 处理程序中恢复的 panic
	// 该函数可用于生成错误页面并返回 HTTP 错误码 500（内部服务器错误）
	// 如果未设置，请求会被委派给 Go 的默认 panic 处理程序，可能会导致服务器崩溃
	PanicHandler func(http.ResponseWriter, *http.Request, interface{})
}

// 这段代码的作用是确保 Router 类型符合 http.Handler 接口的要求。
// 在 Go 语言中，可以通过在类型声明前加上 _ 和接口类型来实现接口类型的隐式实现
// 这里使用了该方法来确保 Router 类型符合 http.Handler 接口。
var _ http.Handler = New()

// New returns a new initialized Router.
// Path auto-correction, including trailing slashes, is enabled by default.
// 这段代码定义了一个名为New()的函数，它返回一个已经初始化的Router对象。
func New() *Router {
	return &Router{
		RedirectTrailingSlash:  true,
		RedirectFixedPath:      true,
		HandleMethodNotAllowed: true,
		HandleOPTIONS:          true,
	}
}

// 这段代码定义了一个 getParams 的方法，返回一个指向 Params 结构体的指针
// 保存了路由匹配到的参数
// 这个方法的目的是重用 Params 结构体，减少内存分配和垃圾回收的压力，提高程序性能。
func (r *Router) getParams() *Params {
	// 使用 sync.Pool 获取一个 Params 结构体
	ps, _ := r.paramsPool.Get().(*Params)
	// 然后将其内容清空
	*ps = (*ps)[0:0] // reset slice
	// 返回这个 Params 结构体
	return ps
}

// 该代码块为 Router 结构体中的 putParams 方法，用于回收 Params 对象。
// 该方法接受一个指向 Params 对象的指针 ps 作为参数。
// 对象池可以帮助减少内存分配和垃圾回收的开销，提高程序的性能和稳定性。
func (r *Router) putParams(ps *Params) {
	if ps != nil {
		// 如果 ps 不为空，则将其放回对象池中，否则不进行任何操作。
		r.paramsPool.Put(ps)
	}
}

// 这个代码块定义了一个名为saveMatchedRoutePath的方法，它的作用是将当前匹配到的路由路径保存到请求的上下文中，并调用原始的路由处理函数。
// 具体地说，这个方法接受一个字符串path表示路由的路径和一个函数句柄handle表示路由的处理函数。
// 在路由请求被处理之前，这个方法会先检查是否开启了SaveMatchedRoutePath选项，
// 如果开启了，那么就会将匹配到的路由路径保存到请求的上下文中。
func (r *Router) saveMatchedRoutePath(path string, handle Handle) Handle {
	return func(w http.ResponseWriter, req *http.Request, ps Params) {
		if ps == nil {
			// 从参数池中获取一个Params切片
			psp := r.getParams()
			// 将匹配到的路由路径作为第一个参数插入到Params中
			ps = (*psp)[0:1]
			// 并调用原始的路由处理函数。
			ps[0] = Param{Key: MatchedRoutePathParam, Value: path}
			handle(w, req, ps)
			// 将Params切片放回参数池中以便重用
			r.putParams(psp)
		} else {
			// 如果Params不为空，则只需要将匹配到的路由路径作为新的参数添加到Params切片中，然后再调用原始的路由处理函数即可。
			ps = append(ps, Param{Key: MatchedRoutePathParam, Value: path})
			handle(w, req, ps)
		}
	}
}

// GET 这段代码定义了 GET 方法，它是一个 Router 类型的方法。
// 它是通过 Handle 方法来实现的，GET 方法实际上是调用了 Handle 方法
// 并将 http.MethodGet 作为参数传递进去，从而让 Router 类型的实例可以处理 GET 请求。
// 因此，使用 GET 方法可以简单地为 Router 实例注册一个 http.MethodGet 方法处理器，
// 即注册一个用于处理 HTTP GET 请求的处理器函数，使其可以处理匹配到的请求路径。
func (r *Router) GET(path string, handle Handle) {
	r.Handle(http.MethodGet, path, handle)
}

// HEAD is a shortcut for router.Handle(http.MethodHead, path, handle)
func (r *Router) HEAD(path string, handle Handle) {
	r.Handle(http.MethodHead, path, handle)
}

// OPTIONS is a shortcut for router.Handle(http.MethodOptions, path, handle)
func (r *Router) OPTIONS(path string, handle Handle) {
	r.Handle(http.MethodOptions, path, handle)
}

// POST is a shortcut for router.Handle(http.MethodPost, path, handle)
func (r *Router) POST(path string, handle Handle) {
	r.Handle(http.MethodPost, path, handle)
}

// PUT is a shortcut for router.Handle(http.MethodPut, path, handle)
func (r *Router) PUT(path string, handle Handle) {
	r.Handle(http.MethodPut, path, handle)
}

// PATCH is a shortcut for router.Handle(http.MethodPatch, path, handle)
func (r *Router) PATCH(path string, handle Handle) {
	r.Handle(http.MethodPatch, path, handle)
}

// DELETE is a shortcut for router.Handle(http.MethodDelete, path, handle)
func (r *Router) DELETE(path string, handle Handle) {
	r.Handle(http.MethodDelete, path, handle)
}

// Handle registers a new request handle with the given path and method.
//
// For GET, POST, PUT, PATCH and DELETE requests the respective shortcut
// functions can be used.
//
// This function is intended for bulk loading and to allow the usage of less
// frequently used, non-standardized or custom methods (e.g. for internal
// communication with a proxy).
func (r *Router) Handle(method, path string, handle Handle) {
	varsCount := uint16(0)

	if method == "" {
		panic("method must not be empty")
	}
	if len(path) < 1 || path[0] != '/' {
		panic("path must begin with '/' in path '" + path + "'")
	}
	if handle == nil {
		panic("handle must not be nil")
	}

	if r.SaveMatchedRoutePath {
		varsCount++
		handle = r.saveMatchedRoutePath(path, handle)
	}

	if r.trees == nil {
		r.trees = make(map[string]*node)
	}

	root := r.trees[method]
	if root == nil {
		root = new(node)
		r.trees[method] = root

		r.globalAllowed = r.allowed("*", "")
	}

	root.addRoute(path, handle)

	// Update maxParams
	if paramsCount := countParams(path); paramsCount+varsCount > r.maxParams {
		r.maxParams = paramsCount + varsCount
	}

	// Lazy-init paramsPool alloc func
	if r.paramsPool.New == nil && r.maxParams > 0 {
		r.paramsPool.New = func() interface{} {
			ps := make(Params, 0, r.maxParams)
			return &ps
		}
	}
}

// Handler is an adapter which allows the usage of an http.Handler as a
// request handle.
// The Params are available in the request context under ParamsKey.
func (r *Router) Handler(method, path string, handler http.Handler) {
	r.Handle(method, path,
		func(w http.ResponseWriter, req *http.Request, p Params) {
			if len(p) > 0 {
				ctx := req.Context()
				ctx = context.WithValue(ctx, ParamsKey, p)
				req = req.WithContext(ctx)
			}
			handler.ServeHTTP(w, req)
		},
	)
}

// HandlerFunc is an adapter which allows the usage of an http.HandlerFunc as a
// request handle.
func (r *Router) HandlerFunc(method, path string, handler http.HandlerFunc) {
	r.Handler(method, path, handler)
}

// ServeFiles serves files from the given file system root.
// The path must end with "/*filepath", files are then served from the local
// path /defined/root/dir/*filepath.
// For example if root is "/etc" and *filepath is "passwd", the local file
// "/etc/passwd" would be served.
// Internally a http.FileServer is used, therefore http.NotFound is used instead
// of the Router's NotFound handler.
// To use the operating system's file system implementation,
// use http.Dir:
//
//	router.ServeFiles("/src/*filepath", http.Dir("/var/www"))
func (r *Router) ServeFiles(path string, root http.FileSystem) {
	if len(path) < 10 || path[len(path)-10:] != "/*filepath" {
		panic("path must end with /*filepath in path '" + path + "'")
	}

	fileServer := http.FileServer(root)

	r.GET(path, func(w http.ResponseWriter, req *http.Request, ps Params) {
		req.URL.Path = ps.ByName("filepath")
		fileServer.ServeHTTP(w, req)
	})
}

func (r *Router) recv(w http.ResponseWriter, req *http.Request) {
	if rcv := recover(); rcv != nil {
		r.PanicHandler(w, req, rcv)
	}
}

// Lookup allows the manual lookup of a method + path combo.
// This is e.g. useful to build a framework around this router.
// If the path was found, it returns the handle function and the path parameter
// values. Otherwise the third return value indicates whether a redirection to
// the same path with an extra / without the trailing slash should be performed.
func (r *Router) Lookup(method, path string) (Handle, Params, bool) {
	if root := r.trees[method]; root != nil {
		handle, ps, tsr := root.getValue(path, r.getParams)
		if handle == nil {
			r.putParams(ps)
			return nil, nil, tsr
		}
		if ps == nil {
			return handle, nil, tsr
		}
		return handle, *ps, tsr
	}
	return nil, nil, false
}

func (r *Router) allowed(path, reqMethod string) (allow string) {
	allowed := make([]string, 0, 9)

	if path == "*" { // server-wide
		// empty method is used for internal calls to refresh the cache
		if reqMethod == "" {
			for method := range r.trees {
				if method == http.MethodOptions {
					continue
				}
				// Add request method to list of allowed methods
				allowed = append(allowed, method)
			}
		} else {
			return r.globalAllowed
		}
	} else { // specific path
		for method := range r.trees {
			// Skip the requested method - we already tried this one
			if method == reqMethod || method == http.MethodOptions {
				continue
			}

			handle, _, _ := r.trees[method].getValue(path, nil)
			if handle != nil {
				// Add request method to list of allowed methods
				allowed = append(allowed, method)
			}
		}
	}

	if len(allowed) > 0 {
		// Add request method to list of allowed methods
		allowed = append(allowed, http.MethodOptions)

		// Sort allowed methods.
		// sort.Strings(allowed) unfortunately causes unnecessary allocations
		// due to allowed being moved to the heap and interface conversion
		for i, l := 1, len(allowed); i < l; i++ {
			for j := i; j > 0 && allowed[j] < allowed[j-1]; j-- {
				allowed[j], allowed[j-1] = allowed[j-1], allowed[j]
			}
		}

		// return as comma separated list
		return strings.Join(allowed, ", ")
	}

	return allow
}

// ServeHTTP makes the router implement the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.PanicHandler != nil {
		defer r.recv(w, req)
	}

	path := req.URL.Path

	if root := r.trees[req.Method]; root != nil {
		if handle, ps, tsr := root.getValue(path, r.getParams); handle != nil {
			if ps != nil {
				handle(w, req, *ps)
				r.putParams(ps)
			} else {
				handle(w, req, nil)
			}
			return
		} else if req.Method != http.MethodConnect && path != "/" {
			// Moved Permanently, request with GET method
			code := http.StatusMovedPermanently
			if req.Method != http.MethodGet {
				// Permanent Redirect, request with same method
				code = http.StatusPermanentRedirect
			}

			if tsr && r.RedirectTrailingSlash {
				if len(path) > 1 && path[len(path)-1] == '/' {
					req.URL.Path = path[:len(path)-1]
				} else {
					req.URL.Path = path + "/"
				}
				http.Redirect(w, req, req.URL.String(), code)
				return
			}

			// Try to fix the request path
			if r.RedirectFixedPath {
				fixedPath, found := root.findCaseInsensitivePath(
					CleanPath(path),
					r.RedirectTrailingSlash,
				)
				if found {
					req.URL.Path = fixedPath
					http.Redirect(w, req, req.URL.String(), code)
					return
				}
			}
		}
	}

	if req.Method == http.MethodOptions && r.HandleOPTIONS {
		// Handle OPTIONS requests
		if allow := r.allowed(path, http.MethodOptions); allow != "" {
			w.Header().Set("Allow", allow)
			if r.GlobalOPTIONS != nil {
				r.GlobalOPTIONS.ServeHTTP(w, req)
			}
			return
		}
	} else if r.HandleMethodNotAllowed { // Handle 405
		if allow := r.allowed(path, req.Method); allow != "" {
			w.Header().Set("Allow", allow)
			if r.MethodNotAllowed != nil {
				r.MethodNotAllowed.ServeHTTP(w, req)
			} else {
				http.Error(w,
					http.StatusText(http.StatusMethodNotAllowed),
					http.StatusMethodNotAllowed,
				)
			}
			return
		}
	}

	// Handle 404
	if r.NotFound != nil {
		r.NotFound.ServeHTTP(w, req)
	} else {
		http.NotFound(w, req)
	}
}
