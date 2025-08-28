package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsRegistry manages Prometheus metrics to prevent duplicate registrations
type MetricsRegistry struct {
	mu                sync.Mutex
	registeredMetrics map[string]prometheus.Collector
}

// NewMetricsRegistry creates a new metrics registry
func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		registeredMetrics: make(map[string]prometheus.Collector),
	}
}

// RegisterCounter registers a counter metric, preventing duplicates
func (mr *MetricsRegistry) RegisterCounter(name string, opts prometheus.CounterOpts, labelNames []string) *prometheus.CounterVec {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	// Check if metric already exists
	if existing, exists := mr.registeredMetrics[name]; exists {
		// Return existing metric if already registered
		if counter, ok := existing.(*prometheus.CounterVec); ok {
			return counter
		}
	}

	// Create new counter
	counter := prometheus.NewCounterVec(opts, labelNames)

	// Register and store
	prometheus.MustRegister(counter)
	mr.registeredMetrics[name] = counter

	return counter
}

// RegisterHistogram registers a histogram metric, preventing duplicates
func (mr *MetricsRegistry) RegisterHistogram(name string, opts prometheus.HistogramOpts, labelNames []string) *prometheus.HistogramVec {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	// Check if metric already exists
	if existing, exists := mr.registeredMetrics[name]; exists {
		// Return existing metric if already registered
		if histogram, ok := existing.(*prometheus.HistogramVec); ok {
			return histogram
		}
	}

	// Create new histogram
	histogram := prometheus.NewHistogramVec(opts, labelNames)

	// Register and store
	prometheus.MustRegister(histogram)
	mr.registeredMetrics[name] = histogram

	return histogram
}

// Global singleton registry
var GlobalRegistry = NewMetricsRegistry()

// Predefined Metrics
var (
	HTTPRequestsTotal = GlobalRegistry.RegisterCounter(
		"http_requests_total",
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = GlobalRegistry.RegisterHistogram(
		"http_request_duration_seconds",
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latencies in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)

	LoginAttempts = GlobalRegistry.RegisterCounter(
		"auth_login_attempts_total",
		prometheus.CounterOpts{
			Name: "auth_login_attempts_total",
			Help: "Total number of login attempts",
		},
		[]string{"method", "status"},
	)

	LoginFailures = GlobalRegistry.RegisterCounter(
		"auth_login_failures_total",
		prometheus.CounterOpts{
			Name: "auth_login_failures_total",
			Help: "Total number of login failures",
		},
		[]string{"method", "reason"},
	)

	RegistrationAttempts = GlobalRegistry.RegisterCounter(
		"auth_registration_attempts_total",
		prometheus.CounterOpts{
			Name: "auth_registration_attempts_total",
			Help: "Total number of registration attempts",
		},
		[]string{"method", "status"},
	)
)
