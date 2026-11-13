package sensor

import "testing"

func TestOutboxStats_Clamp(t *testing.T) {
	cases := []struct {
		name string
		in   OutboxStats
		want OutboxStats
	}{
		{
			name: "in range is unchanged",
			in:   OutboxStats{PendingCount: 3, PendingBytes: 123456, OldestAgeSeconds: 600, DeadLetterCount: 1, EvictedCount: 2},
			want: OutboxStats{PendingCount: 3, PendingBytes: 123456, OldestAgeSeconds: 600, DeadLetterCount: 1, EvictedCount: 2},
		},
		{
			name: "negative becomes zero",
			in:   OutboxStats{PendingCount: -1, PendingBytes: -5, OldestAgeSeconds: -60, DeadLetterCount: -2, EvictedCount: -9},
			want: OutboxStats{},
		},
		{
			name: "absurd values are capped",
			in: OutboxStats{
				PendingCount: 1 << 62, PendingBytes: 1 << 62, OldestAgeSeconds: 1 << 62,
				DeadLetterCount: 1 << 62, EvictedCount: 1 << 62,
			},
			want: OutboxStats{
				PendingCount: MaxOutboxCount, PendingBytes: MaxOutboxBytes, OldestAgeSeconds: MaxOutboxAgeSeconds,
				DeadLetterCount: MaxOutboxCount, EvictedCount: MaxOutboxCount,
			},
		},
		{
			name: "exactly at the cap is kept",
			in:   OutboxStats{PendingCount: MaxOutboxCount, PendingBytes: MaxOutboxBytes, OldestAgeSeconds: MaxOutboxAgeSeconds},
			want: OutboxStats{PendingCount: MaxOutboxCount, PendingBytes: MaxOutboxBytes, OldestAgeSeconds: MaxOutboxAgeSeconds},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Clamp(); got != tc.want {
				t.Errorf("Clamp() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestOutboxStats_Warning(t *testing.T) {
	cases := []struct {
		name string
		in   OutboxStats
		want bool
	}{
		{"empty", OutboxStats{}, false},
		{"pending but fresh", OutboxStats{PendingCount: 50, PendingBytes: 1 << 20, OldestAgeSeconds: 60}, false},
		{"oldest exactly one hour", OutboxStats{PendingCount: 1, OldestAgeSeconds: OutboxWarnOldestAgeSeconds}, false},
		{"oldest over one hour", OutboxStats{PendingCount: 1, OldestAgeSeconds: OutboxWarnOldestAgeSeconds + 1}, true},
		{"dead letter", OutboxStats{DeadLetterCount: 1}, true},
		{"evicted", OutboxStats{EvictedCount: 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Warning(); got != tc.want {
				t.Errorf("Warning() = %v, want %v", got, tc.want)
			}
		})
	}
}
