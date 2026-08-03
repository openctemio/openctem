package unit

import (
	"testing"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/domain/agent"
)

// TestComputeLoadScore_HonorsThroughputCeilings pins that the
// AGENT_LB_MAX_DISK_THROUGHPUT_MBPS / AGENT_LB_MAX_NETWORK_THROUGHPUT_MBPS
// normalization ceilings are honored. They used to be untouchable file-scope
// constants inside ComputeLoadScoreWithWeights, so an operator on NVMe or
// 10 GbE had no way to say what "100% busy" meant on their hardware.
func TestComputeLoadScore_HonorsThroughputCeilings(t *testing.T) {
	t.Parallel()

	a := &agent.Agent{
		MaxConcurrentJobs: 10,
		DiskReadMBPS:      250,
		DiskWriteMBPS:     250, // 500 MB/s combined
		NetworkRxMBPS:     500,
		NetworkTxMBPS:     500, // 1000 MB/s combined
	}

	// Disk-only weights against the default 500 MB/s ceiling: saturated.
	saturated := a.ComputeLoadScoreWithWeights(agent.LoadBalancingWeights{
		DiskIO:                1.0,
		MaxDiskThroughputMBPS: 500,
	})
	if saturated != 100 {
		t.Fatalf("disk score = %v with a 500 MB/s ceiling at 500 MB/s, want 100", saturated)
	}

	// Same traffic on hardware declared 4x faster is only a quarter loaded.
	roomy := a.ComputeLoadScoreWithWeights(agent.LoadBalancingWeights{
		DiskIO:                1.0,
		MaxDiskThroughputMBPS: 2000,
	})
	if roomy != 25 {
		t.Fatalf("disk score = %v with a 2000 MB/s ceiling at 500 MB/s, want 25; "+
			"AGENT_LB_MAX_DISK_THROUGHPUT_MBPS is ignored", roomy)
	}

	net := a.ComputeLoadScoreWithWeights(agent.LoadBalancingWeights{
		Network:                  1.0,
		MaxNetworkThroughputMBPS: 4000,
	})
	if net != 25 {
		t.Fatalf("network score = %v with a 4000 MB/s ceiling at 1000 MB/s, want 25; "+
			"AGENT_LB_MAX_NETWORK_THROUGHPUT_MBPS is ignored", net)
	}
}

// TestLoadBalancingConfig_Weights pins the seam between the parsed AGENT_LB_*
// environment variables and the domain scoring function. Without it the whole
// LoadBalancingConfig struct was write-only: parsed at boot, read by nothing.
func TestLoadBalancingConfig_Weights(t *testing.T) {
	t.Parallel()

	got := config.LoadBalancingConfig{
		JobWeight:                0.11,
		CPUWeight:                0.22,
		MemoryWeight:             0.33,
		DiskIOWeight:             0.44,
		NetworkWeight:            0.55,
		MaxDiskThroughputMBPS:    1234,
		MaxNetworkThroughputMBPS: 5678,
	}.Weights()

	want := agent.LoadBalancingWeights{
		JobLoad:                  0.11,
		CPU:                      0.22,
		Memory:                   0.33,
		DiskIO:                   0.44,
		Network:                  0.55,
		MaxDiskThroughputMBPS:    1234,
		MaxNetworkThroughputMBPS: 5678,
	}
	if got != want {
		t.Fatalf("Weights() = %+v, want %+v", got, want)
	}
}

// TestConfigDefaults_MatchDomainDefaults guards against the config defaults and
// the domain defaults silently drifting apart, which would make the documented
// AGENT_LB_* defaults a lie.
func TestConfigDefaults_MatchDomainDefaults(t *testing.T) {
	t.Parallel()

	def := agent.DefaultLoadBalancingWeights()
	sum := def.JobLoad + def.CPU + def.Memory + def.DiskIO + def.Network
	if sum < 0.999 || sum > 1.001 {
		t.Fatalf("default weights sum to %v, want 1.0", sum)
	}
	if def.IsZero() {
		t.Fatal("default weights report IsZero")
	}
}

// TestUpdateExtendedMetricsWithWeights_UsesConfiguredWeights pins that the
// persisted load_score is computed with the deployment's weights. Heartbeat
// handling previously called UpdateMetrics, which never touched LoadScore at
// all, so the column stayed at whatever it was seeded with.
func TestUpdateExtendedMetricsWithWeights_UsesConfiguredWeights(t *testing.T) {
	t.Parallel()

	a := &agent.Agent{MaxConcurrentJobs: 10}
	a.UpdateExtendedMetricsWithWeights(agent.ExtendedMetrics{
		CPUPercent:    80,
		MemoryPercent: 20,
	}, agent.LoadBalancingWeights{CPU: 1.0})

	if a.LoadScore != 80 {
		t.Fatalf("LoadScore = %v with CPU weighted 1.0 at 80%% CPU, want 80", a.LoadScore)
	}
	if a.MetricsUpdatedAt == nil {
		t.Fatal("MetricsUpdatedAt not stamped; the selector would treat these metrics as stale forever")
	}

	// Memory-dominant weights on the same sample give a different score.
	a.UpdateExtendedMetricsWithWeights(agent.ExtendedMetrics{
		CPUPercent:    80,
		MemoryPercent: 20,
	}, agent.LoadBalancingWeights{Memory: 1.0})

	if a.LoadScore != 20 {
		t.Fatalf("LoadScore = %v with memory weighted 1.0 at 20%% memory, want 20", a.LoadScore)
	}
}
