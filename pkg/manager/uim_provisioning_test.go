package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iniwex5/quectel-qmi-go/pkg/qmi"
)

func TestEnsureSIMProvisioned(t *testing.T) {
	detected := UIMReadiness{CardPresent: true, AppState: qmi.UIMAppStateDetected, NeedsProvisioning: true, Reason: UIMReadinessNeedsProvisioning}
	ready := UIMReadiness{CardPresent: true, AppState: qmi.UIMAppStateReady, ProvisioningActive: true, UIMReady: true, Reason: UIMReadinessReady}
	absent := UIMReadiness{Reason: UIMReadinessCardAbsent}

	t.Run("ready is no-op", func(t *testing.T) {
		rebinds := 0
		deps := ensureProvisioningDeps{
			readiness: func(context.Context) (UIMReadiness, error) { return ready, nil },
			usimAID:   func(context.Context) ([]byte, error) { return []byte{0xA0}, nil },
			rebind:    func(context.Context, uint8, []byte) error { rebinds++; return nil },
			sleep:     func(context.Context, time.Duration) error { return nil },
		}
		r, err := ensureSIMProvisioned(context.Background(), EnsureSIMProvisionedOptions{}, deps)
		if err != nil || !r.UIMReady || rebinds != 0 {
			t.Fatalf("ready no-op failed: r=%+v err=%v rebinds=%d", r, err, rebinds)
		}
	})

	t.Run("detected activates then becomes ready", func(t *testing.T) {
		calls := 0
		rebinds := 0
		deps := ensureProvisioningDeps{
			readiness: func(context.Context) (UIMReadiness, error) {
				calls++
				if calls == 1 {
					return detected, nil
				}
				return ready, nil
			},
			usimAID: func(context.Context) ([]byte, error) { return []byte{0xA0, 0x00, 0x00}, nil },
			rebind:  func(context.Context, uint8, []byte) error { rebinds++; return nil },
			sleep:   func(context.Context, time.Duration) error { return nil },
		}
		r, err := ensureSIMProvisioned(context.Background(), EnsureSIMProvisionedOptions{MaxAttempts: 5}, deps)
		if err != nil || !r.UIMReady || rebinds != 1 {
			t.Fatalf("detected->ready failed: r=%+v err=%v rebinds=%d", r, err, rebinds)
		}
	})

	t.Run("absent is no-op", func(t *testing.T) {
		rebinds := 0
		deps := ensureProvisioningDeps{
			readiness: func(context.Context) (UIMReadiness, error) { return absent, nil },
			usimAID:   func(context.Context) ([]byte, error) { return []byte{0xA0}, nil },
			rebind:    func(context.Context, uint8, []byte) error { rebinds++; return nil },
			sleep:     func(context.Context, time.Duration) error { return nil },
		}
		_, err := ensureSIMProvisioned(context.Background(), EnsureSIMProvisionedOptions{}, deps)
		if err != nil || rebinds != 0 {
			t.Fatalf("absent no-op failed: err=%v rebinds=%d", err, rebinds)
		}
	})

	t.Run("not-supported stops trying, non-fatal", func(t *testing.T) {
		rebinds := 0
		deps := ensureProvisioningDeps{
			readiness: func(context.Context) (UIMReadiness, error) { return detected, nil },
			usimAID:   func(context.Context) ([]byte, error) { return []byte{0xA0}, nil },
			rebind: func(context.Context, uint8, []byte) error {
				rebinds++
				return &qmi.NotSupportedError{Operation: "change provisioning session"}
			},
			sleep: func(context.Context, time.Duration) error { return nil },
		}
		r, err := ensureSIMProvisioned(context.Background(), EnsureSIMProvisionedOptions{MaxAttempts: 5}, deps)
		if err != nil || rebinds != 1 {
			t.Fatalf("not-supported should stop after one try, non-fatal: r=%+v err=%v rebinds=%d", r, err, rebinds)
		}
	})

	t.Run("unknown appstate backstop activates once", func(t *testing.T) {
		unknown := UIMReadiness{CardPresent: true, AppState: qmi.UIMAppStateUnknown, Reason: UIMReadinessCardResetting}
		rebinds := 0
		deps := ensureProvisioningDeps{
			readiness: func(context.Context) (UIMReadiness, error) { return unknown, nil },
			usimAID:   func(context.Context) ([]byte, error) { return []byte{0xA0}, nil },
			rebind:    func(context.Context, uint8, []byte) error { rebinds++; return nil },
			sleep:     func(context.Context, time.Duration) error { return nil },
		}
		_, err := ensureSIMProvisioned(context.Background(), EnsureSIMProvisionedOptions{MaxAttempts: 5, UnknownAppStateBackstop: 3}, deps)
		if err != nil || rebinds != 1 {
			t.Fatalf("unknown backstop should activate exactly once: err=%v rebinds=%d", err, rebinds)
		}
	})

	t.Run("readiness transport error propagates", func(t *testing.T) {
		wantErr := errors.New("qmi: read failed")
		deps := ensureProvisioningDeps{
			readiness: func(context.Context) (UIMReadiness, error) {
				return UIMReadiness{Reason: UIMReadinessTransportFatal}, wantErr
			},
			usimAID: func(context.Context) ([]byte, error) { return nil, nil },
			rebind:  func(context.Context, uint8, []byte) error { return nil },
			sleep:   func(context.Context, time.Duration) error { return nil },
		}
		_, err := ensureSIMProvisioned(context.Background(), EnsureSIMProvisionedOptions{}, deps)
		if !errors.Is(err, wantErr) {
			t.Fatalf("transport error must propagate, got %v", err)
		}
	})
}
