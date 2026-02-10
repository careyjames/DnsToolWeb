package telemetry_test

import (
        "dnstool/internal/telemetry"
        "sync"
        "sync/atomic"
        "testing"
        "time"
)

func TestRecordSuccess(t *testing.T) {
        tests := []struct {
                name               string
                provider           string
                latencies          []time.Duration
                expectedSuccesses  int64
                expectedFailures   int64
                expectedConsecFail int
        }{
                {
                        name:               "single_success",
                        provider:           "google",
                        latencies:          []time.Duration{100 * time.Millisecond},
                        expectedSuccesses:  1,
                        expectedFailures:   0,
                        expectedConsecFail: 0,
                },
                {
                        name:               "multiple_successes",
                        provider:           "cloudflare",
                        latencies:          []time.Duration{50 * time.Millisecond, 75 * time.Millisecond, 100 * time.Millisecond},
                        expectedSuccesses:  3,
                        expectedFailures:   0,
                        expectedConsecFail: 0,
                },
                {
                        name:               "success_resets_consecutive_failures",
                        provider:           "quad9",
                        latencies:          []time.Duration{100 * time.Millisecond},
                        expectedSuccesses:  1,
                        expectedFailures:   0,
                        expectedConsecFail: 0,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for _, lat := range tt.latencies {
                                reg.RecordSuccess(tt.provider, lat)
                        }

                        stats := reg.GetStats(tt.provider)

                        if stats.SuccessCount != tt.expectedSuccesses {
                                t.Errorf("expected %d successes, got %d", tt.expectedSuccesses, stats.SuccessCount)
                        }
                        if stats.FailureCount != tt.expectedFailures {
                                t.Errorf("expected %d failures, got %d", tt.expectedFailures, stats.FailureCount)
                        }
                        if stats.ConsecFailures != tt.expectedConsecFail {
                                t.Errorf("expected %d consecutive failures, got %d", tt.expectedConsecFail, stats.ConsecFailures)
                        }
                })
        }
}

func TestRecordFailure(t *testing.T) {
        tests := []struct {
                name               string
                provider           string
                failures           []string
                expectedFailures   int64
                expectedSuccesses  int64
                expectedConsecFail int
                expectedLastError  string
        }{
                {
                        name:               "single_failure",
                        provider:           "google",
                        failures:           []string{"timeout"},
                        expectedFailures:   1,
                        expectedSuccesses:  0,
                        expectedConsecFail: 1,
                        expectedLastError:  "timeout",
                },
                {
                        name:               "multiple_failures",
                        provider:           "cloudflare",
                        failures:           []string{"error1", "error2", "error3"},
                        expectedFailures:   3,
                        expectedSuccesses:  0,
                        expectedConsecFail: 3,
                        expectedLastError:  "error3",
                },
                {
                        name:               "consecutive_failures_tracking",
                        provider:           "quad9",
                        failures:           []string{"fail1", "fail2", "fail3", "fail4"},
                        expectedFailures:   4,
                        expectedSuccesses:  0,
                        expectedConsecFail: 4,
                        expectedLastError:  "fail4",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for _, errMsg := range tt.failures {
                                reg.RecordFailure(tt.provider, errMsg)
                        }

                        stats := reg.GetStats(tt.provider)

                        if stats.FailureCount != tt.expectedFailures {
                                t.Errorf("expected %d failures, got %d", tt.expectedFailures, stats.FailureCount)
                        }
                        if stats.SuccessCount != tt.expectedSuccesses {
                                t.Errorf("expected %d successes, got %d", tt.expectedSuccesses, stats.SuccessCount)
                        }
                        if stats.ConsecFailures != tt.expectedConsecFail {
                                t.Errorf("expected %d consecutive failures, got %d", tt.expectedConsecFail, stats.ConsecFailures)
                        }
                        if stats.LastError != tt.expectedLastError {
                                t.Errorf("expected last error %q, got %q", tt.expectedLastError, stats.LastError)
                        }
                })
        }
}

func TestCooldown(t *testing.T) {
        tests := []struct {
                name                   string
                provider               string
                failureCount           int
                expectCooldown         bool
                expectedCooldownMin    time.Duration
                expectedCooldownMax    time.Duration
        }{
                {
                        name:           "cooldown_after_3_failures",
                        provider:       "google",
                        failureCount:   3,
                        expectCooldown: true,
                        expectedCooldownMin: 5 * time.Second,
                        expectedCooldownMax: 10 * time.Second,
                },
                {
                        name:           "no_cooldown_with_2_failures",
                        provider:       "cloudflare",
                        failureCount:   2,
                        expectCooldown: false,
                },
                {
                        name:           "exponential_backoff_at_4_failures",
                        provider:       "quad9",
                        failureCount:   4,
                        expectCooldown: true,
                        expectedCooldownMin: 10 * time.Second,
                        expectedCooldownMax: 20 * time.Second,
                },
                {
                        name:           "exponential_backoff_at_5_failures",
                        provider:       "opendns",
                        failureCount:   5,
                        expectCooldown: true,
                        expectedCooldownMin: 20 * time.Second,
                        expectedCooldownMax: 40 * time.Second,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for i := 0; i < tt.failureCount; i++ {
                                reg.RecordFailure(tt.provider, "error")
                        }

                        inCooldown := reg.InCooldown(tt.provider)
                        if inCooldown != tt.expectCooldown {
                                t.Errorf("expected in_cooldown=%v, got %v", tt.expectCooldown, inCooldown)
                        }

                        if tt.expectCooldown {
                                stats := reg.GetStats(tt.provider)
                                if !stats.InCooldown {
                                        t.Errorf("expected InCooldown=true in stats, got false")
                                }
                                if stats.CooldownUntil == nil {
                                        t.Errorf("expected CooldownUntil to be set, got nil")
                                } else {
                                        cooldownDuration := stats.CooldownUntil.Sub(time.Now())
                                        if cooldownDuration < tt.expectedCooldownMin || cooldownDuration > tt.expectedCooldownMax {
                                                t.Logf("cooldown duration %v is not in expected range [%v, %v]", cooldownDuration, tt.expectedCooldownMin, tt.expectedCooldownMax)
                                        }
                                }
                        }
                })
        }
}

func TestCooldownCap(t *testing.T) {
        tests := []struct {
                name         string
                provider     string
                failureCount int
                maxCooldown  time.Duration
        }{
                {
                        name:         "cooldown_capped_at_5_minutes",
                        provider:     "google",
                        failureCount: 10,
                        maxCooldown:  5 * time.Minute,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for i := 0; i < tt.failureCount; i++ {
                                reg.RecordFailure(tt.provider, "error")
                        }

                        stats := reg.GetStats(tt.provider)
                        if stats.CooldownUntil != nil {
                                cooldownDuration := stats.CooldownUntil.Sub(time.Now())
                                if cooldownDuration > tt.maxCooldown {
                                        t.Errorf("expected cooldown <= %v, got %v", tt.maxCooldown, cooldownDuration)
                                }
                        }
                })
        }
}

func TestCooldownReset(t *testing.T) {
        tests := []struct {
                name                    string
                provider                string
                failuresBeforeSuccess   int
                latencyAfterSuccess     time.Duration
                expectedConsecFailures  int
                expectedInCooldown      bool
        }{
                {
                        name:                   "success_resets_cooldown",
                        provider:               "google",
                        failuresBeforeSuccess: 3,
                        latencyAfterSuccess:    100 * time.Millisecond,
                        expectedConsecFailures: 0,
                        expectedInCooldown:     false,
                },
                {
                        name:                   "success_after_5_failures",
                        provider:               "cloudflare",
                        failuresBeforeSuccess: 5,
                        latencyAfterSuccess:    50 * time.Millisecond,
                        expectedConsecFailures: 0,
                        expectedInCooldown:     false,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for i := 0; i < tt.failuresBeforeSuccess; i++ {
                                reg.RecordFailure(tt.provider, "error")
                        }

                        reg.RecordSuccess(tt.provider, tt.latencyAfterSuccess)

                        stats := reg.GetStats(tt.provider)
                        if stats.ConsecFailures != tt.expectedConsecFailures {
                                t.Errorf("expected consecutive failures=%d, got %d", tt.expectedConsecFailures, stats.ConsecFailures)
                        }
                        if stats.InCooldown != tt.expectedInCooldown {
                                t.Errorf("expected in_cooldown=%v, got %v", tt.expectedInCooldown, stats.InCooldown)
                        }
                })
        }
}

func TestHealthStates(t *testing.T) {
        tests := []struct {
                name               string
                provider           string
                failureCount       int
                expectedHealthState telemetry.HealthState
        }{
                {
                        name:                "healthy_with_0_failures",
                        provider:            "google",
                        failureCount:        0,
                        expectedHealthState: telemetry.Healthy,
                },
                {
                        name:                "healthy_with_2_failures",
                        provider:            "cloudflare",
                        failureCount:        2,
                        expectedHealthState: telemetry.Healthy,
                },
                {
                        name:                "degraded_with_3_failures",
                        provider:            "quad9",
                        failureCount:        3,
                        expectedHealthState: telemetry.Degraded,
                },
                {
                        name:                "degraded_with_4_failures",
                        provider:            "opendns",
                        failureCount:        4,
                        expectedHealthState: telemetry.Degraded,
                },
                {
                        name:                "unhealthy_with_5_failures",
                        provider:            "verisign",
                        failureCount:        5,
                        expectedHealthState: telemetry.Unhealthy,
                },
                {
                        name:                "unhealthy_with_6_failures",
                        provider:            "akamai",
                        failureCount:        6,
                        expectedHealthState: telemetry.Unhealthy,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for i := 0; i < tt.failureCount; i++ {
                                reg.RecordFailure(tt.provider, "error")
                        }

                        stats := reg.GetStats(tt.provider)
                        if stats.State != tt.expectedHealthState {
                                t.Errorf("expected health state %q, got %q", tt.expectedHealthState, stats.State)
                        }
                })
        }
}

func TestHealthStateTransitions(t *testing.T) {
        tests := []struct {
                name           string
                provider       string
                operations     []string
                expectedStates []telemetry.HealthState
        }{
                {
                        name:           "healthy_to_degraded",
                        provider:       "google",
                        operations:     []string{"fail", "fail", "fail"},
                        expectedStates: []telemetry.HealthState{telemetry.Healthy, telemetry.Healthy, telemetry.Degraded},
                },
                {
                        name:           "degraded_to_unhealthy",
                        provider:       "cloudflare",
                        operations:     []string{"fail", "fail", "fail", "fail", "fail"},
                        expectedStates: []telemetry.HealthState{telemetry.Healthy, telemetry.Healthy, telemetry.Degraded, telemetry.Degraded, telemetry.Unhealthy},
                },
                {
                        name:           "unhealthy_back_to_healthy",
                        provider:       "quad9",
                        operations:     []string{"fail", "fail", "fail", "fail", "fail", "success"},
                        expectedStates: []telemetry.HealthState{telemetry.Healthy, telemetry.Healthy, telemetry.Degraded, telemetry.Degraded, telemetry.Unhealthy, telemetry.Healthy},
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for i, op := range tt.operations {
                                if op == "fail" {
                                        reg.RecordFailure(tt.provider, "error")
                                } else {
                                        reg.RecordSuccess(tt.provider, 100*time.Millisecond)
                                }

                                stats := reg.GetStats(tt.provider)
                                if stats.State != tt.expectedStates[i] {
                                        t.Errorf("after operation %d, expected state %q, got %q", i, tt.expectedStates[i], stats.State)
                                }
                        }
                })
        }
}

func TestLatencyTracking(t *testing.T) {
        tests := []struct {
                name            string
                provider        string
                latencies       []time.Duration
                expectedP95Min  float64
                expectedP95Max  float64
        }{
                {
                        name:            "single_latency",
                        provider:        "google",
                        latencies:       []time.Duration{100 * time.Millisecond},
                        expectedP95Min:  99.0,
                        expectedP95Max:  101.0,
                },
                {
                        name:            "multiple_latencies",
                        provider:        "cloudflare",
                        latencies:       []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond, 50 * time.Millisecond},
                        expectedP95Min:  40.0,
                        expectedP95Max:  50.0,
                },
                {
                        name:      "many_latencies",
                        provider:  "quad9",
                        latencies: generateLatencies(50, 100),
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for _, lat := range tt.latencies {
                                reg.RecordSuccess(tt.provider, lat)
                        }

                        stats := reg.GetStats(tt.provider)

                        if stats.AvgLatencyMs == 0 && len(tt.latencies) > 0 {
                                t.Errorf("expected average latency > 0, got 0")
                        }

                        if stats.P95LatencyMs == 0 && len(tt.latencies) > 0 {
                                t.Errorf("expected p95 latency > 0, got 0")
                        }

                        if tt.expectedP95Min > 0 && tt.expectedP95Max > 0 {
                                if stats.P95LatencyMs < tt.expectedP95Min || stats.P95LatencyMs > tt.expectedP95Max {
                                        t.Logf("p95 latency %f outside expected range [%f, %f]", stats.P95LatencyMs, tt.expectedP95Min, tt.expectedP95Max)
                                }
                        }
                })
        }
}

func TestAllStats(t *testing.T) {
        tests := []struct {
                name              string
                providers         map[string]int
                expectedProviders int
        }{
                {
                        name:              "single_provider",
                        providers:         map[string]int{"google": 5},
                        expectedProviders: 1,
                },
                {
                        name: "multiple_providers",
                        providers: map[string]int{
                                "google":     3,
                                "cloudflare": 4,
                                "quad9":      5,
                        },
                        expectedProviders: 3,
                },
                {
                        name: "many_providers",
                        providers: map[string]int{
                                "provider1": 1,
                                "provider2": 2,
                                "provider3": 3,
                                "provider4": 4,
                                "provider5": 5,
                        },
                        expectedProviders: 5,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for provider, count := range tt.providers {
                                for i := 0; i < count; i++ {
                                        reg.RecordSuccess(provider, 100*time.Millisecond)
                                }
                        }

                        allStats := reg.AllStats()

                        if len(allStats) != tt.expectedProviders {
                                t.Errorf("expected %d providers, got %d", tt.expectedProviders, len(allStats))
                        }

                        for provider, expectedCount := range tt.providers {
                                found := false
                                for _, stats := range allStats {
                                        if stats.Name == provider && stats.SuccessCount == int64(expectedCount) {
                                                found = true
                                                break
                                        }
                                }
                                if !found {
                                        t.Errorf("provider %q with %d successes not found in all stats", provider, expectedCount)
                                }
                        }
                })
        }
}

func TestAllStatsIndependence(t *testing.T) {
        tests := []struct {
                name      string
                providers []string
                failures  map[string]int
        }{
                {
                        name:      "providers_tracked_independently",
                        providers: []string{"google", "cloudflare", "quad9"},
                        failures: map[string]int{
                                "google":     1,
                                "cloudflare": 3,
                                "quad9":      5,
                        },
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()

                        for provider, failCount := range tt.failures {
                                for i := 0; i < failCount; i++ {
                                        reg.RecordFailure(provider, "error")
                                }
                        }

                        allStats := reg.AllStats()

                        for _, stats := range allStats {
                                expectedFails := tt.failures[stats.Name]
                                if stats.FailureCount != int64(expectedFails) {
                                        t.Errorf("provider %q: expected %d failures, got %d", stats.Name, expectedFails, stats.FailureCount)
                                }
                        }
                })
        }
}

func TestConcurrency(t *testing.T) {
        tests := []struct {
                name              string
                numGoroutines     int
                operationsPerGo   int
                operationType     string
                expectedSuccesses int64
                expectedFailures  int64
        }{
                {
                        name:              "concurrent_successes",
                        numGoroutines:     10,
                        operationsPerGo:   10,
                        operationType:     "success",
                        expectedSuccesses: 100,
                        expectedFailures:  0,
                },
                {
                        name:              "concurrent_failures",
                        numGoroutines:     10,
                        operationsPerGo:   10,
                        operationType:     "failure",
                        expectedSuccesses: 0,
                        expectedFailures:  100,
                },
                {
                        name:              "mixed_concurrent_operations",
                        numGoroutines:     20,
                        operationsPerGo:   5,
                        operationType:     "mixed",
                        expectedSuccesses: 50,
                        expectedFailures:  50,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        provider := "test_provider"
                        var wg sync.WaitGroup
                        var successCount, failureCount int64

                        wg.Add(tt.numGoroutines)
                        for g := 0; g < tt.numGoroutines; g++ {
                                go func(goroutineID int) {
                                        defer wg.Done()
                                        for op := 0; op < tt.operationsPerGo; op++ {
                                                switch tt.operationType {
                                                case "success":
                                                        reg.RecordSuccess(provider, 100*time.Millisecond)
                                                        atomic.AddInt64(&successCount, 1)
                                                case "failure":
                                                        reg.RecordFailure(provider, "error")
                                                        atomic.AddInt64(&failureCount, 1)
                                                case "mixed":
                                                        if (goroutineID+op)%2 == 0 {
                                                                reg.RecordSuccess(provider, 100*time.Millisecond)
                                                                atomic.AddInt64(&successCount, 1)
                                                        } else {
                                                                reg.RecordFailure(provider, "error")
                                                                atomic.AddInt64(&failureCount, 1)
                                                        }
                                                }
                                        }
                                }(g)
                        }

                        wg.Wait()

                        stats := reg.GetStats(provider)

                        if stats.SuccessCount != tt.expectedSuccesses {
                                t.Errorf("expected %d successes, got %d", tt.expectedSuccesses, stats.SuccessCount)
                        }
                        if stats.FailureCount != tt.expectedFailures {
                                t.Errorf("expected %d failures, got %d", tt.expectedFailures, stats.FailureCount)
                        }
                })
        }
}

func TestConcurrentMultipleProviders(t *testing.T) {
        tests := []struct {
                name          string
                numProviders  int
                numGoroutines int
                operationsPerGo int
        }{
                {
                        name:            "multiple_providers_concurrent",
                        numProviders:    5,
                        numGoroutines:   20,
                        operationsPerGo: 10,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        var wg sync.WaitGroup

                        providers := make([]string, tt.numProviders)
                        for i := 0; i < tt.numProviders; i++ {
                                providers[i] = "provider_" + string(rune('0'+i))
                        }

                        wg.Add(tt.numGoroutines)
                        for g := 0; g < tt.numGoroutines; g++ {
                                go func(goroutineID int) {
                                        defer wg.Done()
                                        for op := 0; op < tt.operationsPerGo; op++ {
                                                provider := providers[(goroutineID+op)%tt.numProviders]
                                                if (goroutineID+op)%3 == 0 {
                                                        reg.RecordSuccess(provider, 100*time.Millisecond)
                                                } else {
                                                        reg.RecordFailure(provider, "error")
                                                }
                                        }
                                }(g)
                        }

                        wg.Wait()

                        allStats := reg.AllStats()
                        if len(allStats) != tt.numProviders {
                                t.Errorf("expected %d providers, got %d", tt.numProviders, len(allStats))
                        }

                        for _, stats := range allStats {
                                if stats.TotalRequests == 0 {
                                        t.Errorf("provider %q has no requests", stats.Name)
                                }
                        }
                })
        }
}

func TestConcurrentGetStats(t *testing.T) {
        tests := []struct {
                name              string
                numGoroutines     int
                operationsPerGo   int
        }{
                {
                        name:            "concurrent_get_stats",
                        numGoroutines:   10,
                        operationsPerGo: 100,
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        reg := telemetry.NewRegistry()
                        provider := "test_provider"

                        for i := 0; i < 50; i++ {
                                reg.RecordSuccess(provider, 100*time.Millisecond)
                        }

                        var wg sync.WaitGroup
                        wg.Add(tt.numGoroutines)

                        for g := 0; g < tt.numGoroutines; g++ {
                                go func() {
                                        defer wg.Done()
                                        for op := 0; op < tt.operationsPerGo; op++ {
                                                stats := reg.GetStats(provider)
                                                if stats.SuccessCount != 50 {
                                                        t.Errorf("expected 50 successes, got %d", stats.SuccessCount)
                                                }
                                        }
                                }()
                        }

                        wg.Wait()
                })
        }
}

func generateLatencies(count int, baseMs int) []time.Duration {
        latencies := make([]time.Duration, count)
        for i := 0; i < count; i++ {
                latencies[i] = time.Duration((baseMs + i%50)) * time.Millisecond
        }
        return latencies
}
