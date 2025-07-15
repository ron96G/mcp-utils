package storage

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/ron96g/mcp-utils/pkg/log"
)

// SessionStore interface for storing temporary session data
type SessionStore interface {
	Set(key string, value interface{}, ttl time.Duration) error
	Get(key string) (interface{}, error)
	Delete(key string) error
	Exists(key string) bool
	Clear() error
	GetStats() map[string]interface{}
	// CompareAndSet atomically updates a value only if it matches the expected value
	CompareAndSet(key string, expected, new interface{}, ttl time.Duration) (bool, error)
}

// SessionEntry represents a stored session entry
type SessionEntry struct {
	Value     interface{} `json:"value"`
	ExpiresAt time.Time   `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}

// IsExpired returns true if the session entry has expired
func (se *SessionEntry) IsExpired() bool {
	return time.Now().After(se.ExpiresAt)
}

// compareValues performs deep comparison of two values
func compareValues(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}

// memorySessionStore implements SessionStore using in-memory storage
type memorySessionStore struct {
	data   map[string]*SessionEntry
	mu     sync.RWMutex
	logger *log.Logger
}

// NewMemorySessionStore creates a new in-memory session store
func NewMemorySessionStore() SessionStore {
	store := &memorySessionStore{
		data:   make(map[string]*SessionEntry),
		logger: log.WithComponent("session_store"),
	}

	// Start cleanup goroutine
	go store.cleanupWorker()

	return store
}

// Set stores a value with the given key and TTL
func (s *memorySessionStore) Set(key string, value interface{}, ttl time.Duration) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("TTL must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entry := &SessionEntry{
		Value:     value,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	s.data[key] = entry

	s.logger.Debug().
		Str("key", key).
		Dur("ttl", ttl).
		Time("expires_at", entry.ExpiresAt).
		Msg("Session entry stored")

	return nil
}

// Get retrieves a value by key
func (s *memorySessionStore) Get(key string) (interface{}, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.data[key]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	if entry.IsExpired() {
		// Clean up expired entry
		s.mu.RUnlock()
		s.mu.Lock()
		delete(s.data, key)
		s.mu.Unlock()
		s.mu.RLock()

		s.logger.Debug().
			Str("key", key).
			Msg("Expired session entry removed during get")

		return nil, fmt.Errorf("key expired")
	}

	s.logger.Debug().
		Str("key", key).
		Time("expires_at", entry.ExpiresAt).
		Msg("Session entry retrieved")

	return entry.Value, nil
}

// Delete removes a key from the store
func (s *memorySessionStore) Delete(key string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[key]; !exists {
		return fmt.Errorf("key not found")
	}

	delete(s.data, key)

	s.logger.Debug().
		Str("key", key).
		Msg("Session entry deleted")

	return nil
}

// Exists checks if a key exists and is not expired
func (s *memorySessionStore) Exists(key string) bool {
	if key == "" {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.data[key]
	if !exists {
		return false
	}

	return !entry.IsExpired()
}

// Clear removes all entries from the store
func (s *memorySessionStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := len(s.data)
	s.data = make(map[string]*SessionEntry)

	s.logger.Info().
		Int("cleared_count", count).
		Msg("All session entries cleared")

	return nil
}

// GetStats returns statistics about the session store
func (s *memorySessionStore) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalEntries := len(s.data)
	expiredEntries := 0
	activeEntries := 0

	now := time.Now()
	oldestEntry := now
	newestEntry := time.Time{}

	for _, entry := range s.data {
		if entry.IsExpired() {
			expiredEntries++
		} else {
			activeEntries++
		}

		if entry.CreatedAt.Before(oldestEntry) {
			oldestEntry = entry.CreatedAt
		}

		if entry.CreatedAt.After(newestEntry) {
			newestEntry = entry.CreatedAt
		}
	}

	stats := map[string]interface{}{
		"total_entries":   totalEntries,
		"active_entries":  activeEntries,
		"expired_entries": expiredEntries,
	}

	if totalEntries > 0 {
		stats["oldest_entry"] = oldestEntry
		stats["newest_entry"] = newestEntry
	}

	return stats
}

// CompareAndSet atomically updates a value only if it matches the expected value
func (s *memorySessionStore) CompareAndSet(key string, expected, new interface{}, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, fmt.Errorf("key cannot be empty")
	}

	if ttl <= 0 {
		return false, fmt.Errorf("TTL must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.data[key]
	if !exists {
		return false, fmt.Errorf("key not found")
	}

	if entry.IsExpired() {
		delete(s.data, key)
		return false, fmt.Errorf("key expired")
	}

	// Compare the current value with expected value
	// We use a deep comparison approach for the authorization code data
	if !compareValues(entry.Value, expected) {
		s.logger.Debug().
			Str("key", key).
			Msg("CompareAndSet failed: value mismatch")
		return false, nil // Not an error, just didn't match
	}

	// Values match, update to new value
	now := time.Now()
	newEntry := &SessionEntry{
		Value:     new,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	s.data[key] = newEntry

	s.logger.Debug().
		Str("key", key).
		Dur("ttl", ttl).
		Msg("CompareAndSet succeeded")

	return true, nil
}

// cleanupWorker periodically removes expired entries
func (s *memorySessionStore) cleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupExpired()
	}
}

// cleanupExpired removes all expired entries
func (s *memorySessionStore) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	for key, entry := range s.data {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(s.data, key)
	}

	if len(expiredKeys) > 0 {
		s.logger.Debug().
			Int("expired_count", len(expiredKeys)).
			Int("remaining_count", len(s.data)).
			Msg("Expired session entries cleaned up")
	}
}

// redisSessionStore implements SessionStore using Redis (placeholder for future implementation)
type redisSessionStore struct {
	// Redis client would go here
	logger *log.Logger
}

// NewRedisSessionStore creates a new Redis-based session store
func NewRedisSessionStore(redisURL string) (SessionStore, error) {
	// This would be implemented when Redis support is needed
	return nil, fmt.Errorf("Redis session store not implemented yet")
}

// SessionStoreConfig holds configuration for session stores
type SessionStoreConfig struct {
	Type            string        `yaml:"type"`             // "memory" or "redis"
	DefaultTTL      time.Duration `yaml:"default_ttl"`      // Default TTL for sessions
	CleanupInterval time.Duration `yaml:"cleanup_interval"` // How often to cleanup expired entries

	// Redis configuration (if using Redis)
	RedisURL      string `yaml:"redis_url"`
	RedisPassword string `yaml:"redis_password"`
	RedisDB       int    `yaml:"redis_db"`
	RedisPrefix   string `yaml:"redis_prefix"`
}

// DefaultSessionStoreConfig returns default configuration
func DefaultSessionStoreConfig() *SessionStoreConfig {
	return &SessionStoreConfig{
		Type:            "memory",
		DefaultTTL:      10 * time.Minute,
		CleanupInterval: 5 * time.Minute,
		RedisPrefix:     "mcp_session:",
	}
}

// NewSessionStore creates a new session store based on configuration
func NewSessionStore(config *SessionStoreConfig) (SessionStore, error) {
	if config == nil {
		config = DefaultSessionStoreConfig()
	}

	switch config.Type {
	case "memory":
		return NewMemorySessionStore(), nil
	case "redis":
		return NewRedisSessionStore(config.RedisURL)
	default:
		return nil, fmt.Errorf("unsupported session store type: %s", config.Type)
	}
}
