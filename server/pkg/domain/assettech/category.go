package assettech

import "strings"

// Category is the closed set of technology categories. Producers send their
// own, open taxonomies (or none: httpx reports bare names); Classify maps
// them onto this set.
type Category string

// Categories, in the order the console groups them.
const (
	CategoryWebServer      Category = "web_server"
	CategoryFramework      Category = "framework" // framework or CMS
	CategoryLanguage       Category = "language"  // language or runtime
	CategoryJSLibrary      Category = "js_library"
	CategoryCDN            Category = "cdn"
	CategoryHosting        Category = "hosting" // hosting or PaaS
	CategoryWAF            Category = "waf"     // WAF or security service
	CategoryAnalytics      Category = "analytics"
	CategorySecurityHeader Category = "security_header"
	CategoryOther          Category = "other"
)

// AllCategories lists the categories in display order.
func AllCategories() []Category {
	return []Category{
		CategoryWebServer, CategoryFramework, CategoryLanguage, CategoryJSLibrary,
		CategoryCDN, CategoryHosting, CategoryWAF, CategoryAnalytics,
		CategorySecurityHeader, CategoryOther,
	}
}

// IsValid reports whether c is one of the categories.
func (c Category) IsValid() bool {
	for _, x := range AllCategories() {
		if c == x {
			return true
		}
	}
	return false
}

// Kind is what a category's technologies are for the platform.
type Kind string

const (
	// KindSoftware: a product that runs on the asset; with a version or a
	// CPE it is also a software component (CVE matching).
	KindSoftware Kind = "software"
	// KindInfrastructure: who hosts, fronts or filters the asset.
	KindInfrastructure Kind = "infrastructure"
	// KindHTTPSecurity: an HTTP security control the asset sends.
	KindHTTPSecurity Kind = "http_security"
	// KindMarketing: analytics and marketing tags.
	KindMarketing Kind = "marketing"
)

// Kind is the category's kind.
func (c Category) Kind() Kind {
	switch c {
	case CategoryCDN, CategoryHosting, CategoryWAF:
		return KindInfrastructure
	case CategorySecurityHeader:
		return KindHTTPSecurity
	case CategoryAnalytics:
		return KindMarketing
	}
	return KindSoftware
}

// ParseCategories splits a comma-separated category filter, keeping only
// valid categories.
func ParseCategories(raw string) []Category {
	parts := strings.Split(raw, ",")
	out := make([]Category, 0, len(parts))
	seen := map[Category]bool{}
	for _, p := range parts {
		c := Category(strings.ToLower(strings.TrimSpace(p)))
		if !c.IsValid() || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// Classify is the category of a technology: the curated name list first
// (it knows that "HSTS" is a security header whatever a tool files it
// under), then the tool's own categories, else other. key is a Key.
func Classify(key string, toolCategories []string) Category {
	if c, ok := curatedNames[key]; ok {
		return c
	}
	for _, tc := range toolCategories {
		if c, ok := toolCategoryMap[normCategory(tc)]; ok {
			return c
		}
	}
	return CategoryOther
}

func normCategory(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("-", " ", "_", " ").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// toolCategoryMap maps the category names fingerprinting tools use (the
// common web technology taxonomy, in either "Web servers" or "web-server"
// spelling) onto the closed set.
var toolCategoryMap = func() map[string]Category {
	m := map[string]Category{}
	add := func(c Category, names ...string) {
		for _, n := range names {
			m[normCategory(n)] = c
		}
	}
	add(CategoryWebServer, "web servers", "web server", "reverse proxies", "reverse proxy",
		"web server extensions", "load balancers", "load balancer", "caching", "cache tools", "application servers")
	add(CategoryFramework, "cms", "ecommerce", "blogs", "web frameworks", "web framework", "framework",
		"static site generator", "wikis", "lms", "message boards", "page builders", "photo galleries",
		"documentation", "headless cms", "issue trackers", "webmail", "dms", "hosting panels")
	add(CategoryLanguage, "programming languages", "programming language", "language", "runtime")
	add(CategoryJSLibrary, "javascript frameworks", "javascript libraries", "javascript library",
		"js library", "ui frameworks", "javascript graphics", "rich text editors", "font scripts", "maps",
		"video players", "miscellaneous javascript")
	add(CategoryCDN, "cdn")
	add(CategoryHosting, "paas", "iaas", "hosting", "cloud", "cloud hosting", "platform as a service")
	add(CategoryWAF, "security", "waf", "web application firewall", "captchas", "bot protection")
	add(CategoryAnalytics, "analytics", "marketing automation", "advertising", "tag managers",
		"live chat", "rum", "customer data platform", "a/b testing", "retargeting", "affiliate programs",
		"crm", "surveys", "cookie compliance", "personalisation", "segmentation", "heatmaps", "marketing")
	add(CategorySecurityHeader, "security header", "security headers", "http security header")
	return m
}()

// curatedNames are the categories of common technologies by key. A name
// not listed falls back to the tool's categories.
var curatedNames = func() map[string]Category {
	m := map[string]Category{}
	add := func(c Category, names ...string) {
		for _, n := range names {
			m[Key(n)] = c
		}
	}
	add(CategorySecurityHeader, "HSTS", "HTTP Strict Transport Security", "Strict-Transport-Security",
		"Content Security Policy", "Content-Security-Policy", "CSP", "X-Frame-Options",
		"X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy",
		"Feature-Policy", "Expect-CT", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy")
	add(CategoryHosting, "Vercel", "Netlify", "Heroku", "GitHub Pages", "GitLab Pages", "Firebase",
		"Firebase Hosting", "Google Cloud", "Google Cloud Platform", "Google App Engine", "Amazon Web Services",
		"AWS", "Amazon S3", "Amazon ELB", "Amazon ALB", "AWS Elastic Beanstalk", "AWS Amplify", "Azure",
		"Microsoft Azure", "Azure App Service", "Azure Static Web Apps", "DigitalOcean", "DigitalOcean Spaces",
		"Render", "Fly.io", "Cloudflare Pages", "Cloudflare Workers", "WP Engine", "Pantheon", "Kinsta",
		"Acquia Cloud Platform", "Platform.sh", "Oracle Cloud", "Alibaba Cloud", "OVHcloud", "Hetzner",
		"Linode", "Akamai Connected Cloud", "Railway", "Surge", "Wix", "Squarespace", "Webflow",
		"Shopify", "HubSpot CMS Hub", "Ghost(Pro)", "Bitbucket Pages")
	add(CategoryCDN, "Cloudflare", "Amazon CloudFront", "CloudFront", "Akamai", "Fastly", "jsDelivr",
		"unpkg", "cdnjs", "Google Hosted Libraries", "StackPath", "BunnyCDN", "bunny.net", "KeyCDN",
		"Azure CDN", "Azure Front Door", "Edgio", "EdgeCast", "Limelight", "CacheFly", "Cloudinary",
		"imgix", "Gcore", "CDN77", "Sucuri CDN", "Vercel Edge Network", "Netlify Edge")
	add(CategoryWAF, "Cloudflare Bot Management", "Imperva", "Incapsula", "Sucuri", "Akamai Bot Manager",
		"Kona Site Defender", "AWS WAF", "Azure Web Application Firewall", "F5 BIG-IP", "BIG-IP",
		"Barracuda", "ModSecurity", "Wordfence", "reCAPTCHA", "hCaptcha", "Cloudflare Turnstile",
		"DataDome", "PerimeterX", "HUMAN", "Kasada", "FortiWeb", "Citrix NetScaler", "NetScaler",
		"Radware", "Wallarm", "Signal Sciences", "Reblaze", "Shape Security")
	add(CategoryAnalytics, "Google Analytics", "Google Tag Manager", "Google Ads", "Google Ads Conversion Tracking",
		"Google AdSense", "DoubleClick", "Facebook Pixel", "Meta Pixel", "Hotjar", "Segment", "Mixpanel",
		"Amplitude", "Matomo", "Matomo Analytics", "Piwik", "HubSpot", "HubSpot Analytics", "LinkedIn Insight Tag",
		"Microsoft Clarity", "Adobe Analytics", "Adobe Experience Platform Launch", "New Relic", "Datadog",
		"Sentry", "Intercom", "Drift", "Zendesk", "Optimizely", "Plausible", "FullStory", "Heap",
		"Quantcast", "Twitter Ads", "TikTok Pixel", "Yandex.Metrika", "Cloudflare Browser Insights",
		"Crazy Egg", "Mouseflow", "Klaviyo", "Mailchimp", "Marketo", "Pardot", "Google Optimize",
		"OneTrust", "Cookiebot", "CookieYes", "Osano", "Termly", "Bing Ads", "Pinterest Tag", "Snap Pixel",
		"Tealium", "Smartlook", "LiveChat", "Tawk.to", "Crisp", "Elastic APM", "Dynatrace", "AppDynamics")
	add(CategoryWebServer, "nginx", "Apache", "Apache HTTP Server", "Apache httpd", "Microsoft-IIS", "IIS",
		"LiteSpeed", "OpenLiteSpeed", "OpenResty", "Caddy", "Envoy", "Apache Tomcat", "Tomcat", "Jetty",
		"Gunicorn", "Uvicorn", "lighttpd", "Tengine", "H2O", "Traefik", "HAProxy", "Kestrel", "Cowboy",
		"Puma", "Unicorn", "Phusion Passenger", "WEBrick", "Varnish", "Squid", "Oracle HTTP Server",
		"IBM HTTP Server", "Oracle WebLogic Server", "WebLogic", "JBoss", "WildFly", "GlassFish",
		"IBM WebSphere", "Werkzeug", "Node.js http-server", "Cherokee", "Zeus", "nginx Unit", "Kong",
		"Apache Traffic Server", "Hiawatha", "Mongoose", "thttpd", "Resin")
	add(CategoryFramework, "WordPress", "Drupal", "Joomla", "Magento", "Adobe Commerce", "Ghost", "TYPO3",
		"Umbraco", "Sitecore", "Adobe Experience Manager", "Contentful", "Strapi", "Laravel", "Symfony",
		"Django", "Flask", "FastAPI", "Ruby on Rails", "Express", "Next.js", "Nuxt.js", "Nuxt", "Gatsby",
		"ASP.NET", "ASP.NET Core", "ASP.NET MVC", "Spring", "Spring Boot", "CodeIgniter", "CakePHP",
		"Yii", "Zend", "Laminas", "PrestaShop", "OpenCart", "WooCommerce", "BigCommerce", "Moodle",
		"MediaWiki", "Docusaurus", "Hugo", "Jekyll", "Astro", "Remix", "SvelteKit", "Angular Universal",
		"Phoenix", "Play Framework", "Koa", "NestJS", "Hapi", "Sails.js", "Meteor", "Craft CMS",
		"Concrete CMS", "Kentico", "DNN", "Liferay", "Plone", "Shopware", "SilverStripe", "Grav",
		"October CMS", "ProcessWire", "Bitrix", "1C-Bitrix", "Directus", "Sanity", "Storyblok",
		"Prismic", "Payload CMS", "Blazor", "Vaadin", "Struts", "Apache Struts", "JSF", "Grails",
		"Elementor", "Divi", "Yoast SEO", "WPML", "Gutenberg")
	add(CategoryLanguage, "PHP", "Python", "Ruby", "Java", "Node.js", "Go", "Perl", "Erlang", "Elixir",
		"Lua", "Scala", "Kotlin", "Rust", "Deno", "Bun", ".NET", "Microsoft .NET", "ColdFusion",
		"Adobe ColdFusion", "Lucee", "OpenSSL", "mod_ssl", "mod_perl", "mod_wsgi", "Phusion")
	add(CategoryJSLibrary, "jQuery", "jQuery UI", "jQuery Migrate", "jQuery Mobile", "React", "Vue.js",
		"Vue", "AngularJS", "Angular", "Bootstrap", "Lodash", "Underscore.js", "Moment.js", "core-js",
		"Axios", "D3", "Three.js", "Alpine.js", "htmx", "Svelte", "Ember.js", "Backbone.js", "RequireJS",
		"Modernizr", "Swiper", "Slick", "Owl Carousel", "Select2", "Font Awesome", "webpack", "Vite",
		"Polyfill", "Prototype", "MooTools", "Popper", "GSAP", "Lightbox", "Hammer.js", "Chart.js",
		"Zepto", "Handlebars", "Mustache", "Knockout.js", "Preact", "Socket.io", "Stimulus", "Turbo",
		"Emotion", "styled-components", "Tailwind CSS", "Bulma", "Foundation", "Materialize CSS",
		"Material UI", "MUI", "Ant Design", "Semantic UI", "UIkit", "Lazy.js", "lazysizes", "Isotope",
		"Masonry", "FancyBox", "Magnific Popup", "Video.js", "Plyr", "TinyMCE", "CKEditor", "Quill",
		"Leaflet", "Mapbox GL JS", "Google Maps", "Highcharts", "ECharts", "Day.js", "Immer", "Redux",
		"MobX", "RxJS", "Zone.js", "Hotwire", "Livewire", "Inertia.js", "SolidJS", "Lit", "Stencil",
		"Ionic", "Framer Motion", "AOS", "Clipboard.js", "SweetAlert", "SweetAlert2", "Toastr",
		"DataTables", "Flickity", "Glide.js", "Splide", "PhotoSwipe", "Google Font API", "Bootstrap Icons")
	return m
}()
