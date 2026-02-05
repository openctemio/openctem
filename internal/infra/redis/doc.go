// Package redis provides production-ready Redis integration for the Exploop application.
//
// # Overview
//
// This package provides four main components:
//   - Client: Connection management with TLS, pooling, and retry logic
//   - Cache[T]: Type-safe generic caching with TTL support
//   - TokenStore: JWT blacklist, session management, and refresh tokens
//   - RateLimiter: Distributed rate limiting using sliding window algorithm
//
// # Quick Start
//
// Initialize the Redis client:
//
//	cfg := &config.RedisConfig{
//		Host:          "localhost",
//		Port:          6379,
//		Password:      "secret",
//		DB:            0,
//		PoolSize:      10,
//		MinIdleConns:  2,
//		DialTimeout:   5 * time.Second,
//		ReadTimeout:   3 * time.Second,
//		WriteTimeout:  3 * time.Second,
//		TLSEnabled:    true,  // Required in production
//		TLSSkipVerify: false, // Must be false in production
//		MaxRetries:    3,
//		MinRetryDelay: 100 * time.Millisecond,
//		MaxRetryDelay: 3 * time.Second,
//	}
//
//	client, err := redis.New(cfg, logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
// # Using the Generic Cache
//
// Create a type-safe cache for any struct:
//
//	type User struct {
//		ID    string `json:"id"`
//		Name  string `json:"name"`
//		Email string `json:"email"`
//	}
//
//	// Create cache with 1 hour TTL
//	userCache, err := redis.NewCache[User](client, "users", time.Hour)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Store a user
//	user := User{ID: "123", Name: "John", Email: "john@example.com"}
//	if err := userCache.Set(ctx, user.ID, user); err != nil {
//		log.Error("failed to cache user", "error", err)
//	}
//
//	// Retrieve a user
//	cached, err := userCache.Get(ctx, "123")
//	if errors.Is(err, redis.ErrCacheMiss) {
//		// Cache miss - load from database
//	} else if err != nil {
//		log.Error("cache error", "error", err)
//	}
//
//	// Get or set pattern (cache-aside)
//	user, err := userCache.GetOrSet(ctx, "123", func(ctx context.Context) (*User, error) {
//		return userRepo.FindByID(ctx, "123")
//	})
//
// # Using the Token Store
//
// Manage JWT blacklist and sessions:
//
//	tokenStore, err := redis.NewTokenStore(client, logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Blacklist a JWT token (for logout)
//	err = tokenStore.BlacklistToken(ctx, jti, tokenExpiry)
//
//	// Check if token is blacklisted (in auth middleware)
//	blacklisted, err := tokenStore.IsBlacklisted(ctx, jti)
//	if blacklisted {
//		return ErrTokenRevoked
//	}
//
//	// Store user session
//	sessionData := map[string]string{
//		"user_agent": r.UserAgent(),
//		"ip":         r.RemoteAddr,
//		"created_at": time.Now().Format(time.RFC3339),
//	}
//	err = tokenStore.StoreSession(ctx, userID, sessionID, sessionData, 24*time.Hour)
//
//	// Delete all sessions (force logout from all devices)
//	err = tokenStore.DeleteAllUserSessions(ctx, userID)
//
//	// Refresh token rotation
//	err = tokenStore.RotateRefreshToken(ctx, userID, oldHash, newHash, 7*24*time.Hour)
//
// # Using the Rate Limiter
//
// Distributed rate limiting:
//
//	rateLimiter, err := redis.NewRateLimiter(
//		client,
//		"api",           // key prefix
//		100,             // 100 requests
//		time.Minute,     // per minute
//		logger,
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// In HTTP middleware
//	result, err := rateLimiter.Allow(ctx, clientIP)
//	if err != nil {
//		// Redis error - decide on fallback strategy
//		log.Error("rate limit check failed", "error", err)
//	}
//	if !result.Allowed {
//		w.Header().Set("Retry-After", result.RetryAt.Format(time.RFC1123))
//		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
//		return
//	}
//	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
//
// # Production Configuration
//
// Required settings for production:
//
//	# .env (production)
//	REDIS_HOST=redis.internal
//	REDIS_PORT=6379
//	REDIS_PASSWORD=<strong-password>
//	REDIS_DB=0
//	REDIS_POOL_SIZE=25
//	REDIS_MIN_IDLE_CONNS=5
//	REDIS_DIAL_TIMEOUT=5s
//	REDIS_READ_TIMEOUT=3s
//	REDIS_WRITE_TIMEOUT=3s
//	REDIS_TLS_ENABLED=true
//	REDIS_TLS_SKIP_VERIFY=false
//	REDIS_MAX_RETRIES=3
//	REDIS_MIN_RETRY_DELAY=100ms
//	REDIS_MAX_RETRY_DELAY=3s
//
// # Health Checks
//
// Use the Ping method for health checks:
//
//	func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
//		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
//		defer cancel()
//
//		if err := h.redis.Ping(ctx); err != nil {
//			http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
//			return
//		}
//		w.WriteHeader(http.StatusOK)
//	}
//
// # Error Handling
//
// The package defines specific errors for common cases:
//
//	var (
//		ErrKeyNotFound = errors.New("redis: key not found")
//		ErrCacheMiss   = errors.New("cache: key not found")
//	)
//
// Use errors.Is for error checking:
//
//	if errors.Is(err, redis.ErrCacheMiss) {
//		// Handle cache miss
//	}
//
// # Thread Safety
//
// All components are safe for concurrent use. The underlying go-redis client
// manages connection pooling automatically.
//
// # Graceful Shutdown
//
// Always close the client on application shutdown:
//
//	// In main.go
//	sigChan := make(chan os.Signal, 1)
//	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
//	<-sigChan
//
//	// Graceful shutdown
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	if err := redisClient.Close(); err != nil {
//		log.Error("failed to close redis", "error", err)
//	}
package redis
