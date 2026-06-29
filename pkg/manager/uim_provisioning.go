package manager

import (
	"context"
	"errors"
	"time"

	"github.com/iniwex5/quectel-qmi-go/pkg/qmi"
)

// EnsureSIMProvisionedOptions 控制 provisioning 收敛的轮询节奏。
type EnsureSIMProvisionedOptions struct {
	DefaultSlot             uint8
	PollInterval            time.Duration
	MaxAttempts             int
	UnknownAppStateBackstop int
}

func normalizeEnsureSIMProvisionedOptions(o EnsureSIMProvisionedOptions) EnsureSIMProvisionedOptions {
	if o.DefaultSlot == 0 {
		o.DefaultSlot = 1
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 500 * time.Millisecond
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 10
	}
	if o.UnknownAppStateBackstop <= 0 {
		o.UnknownAppStateBackstop = 3
	}
	return o
}

type ensureProvisioningDeps struct {
	readiness func(context.Context) (UIMReadiness, error)
	usimAID   func(context.Context) ([]byte, error)
	rebind    func(ctx context.Context, slot uint8, aid []byte) error
	sleep     func(ctx context.Context, d time.Duration) error
}

// EnsureSIMProvisioned 幂等地把 USIM 从 detected 收敛到 ready：
// 仅当卡在场且应用 detected（或 AppState 未知且持续未就绪）时才激活
// primary-gw provisioning session；对已 ready 设备完全 no-op。
func (m *Manager) EnsureSIMProvisioned(ctx context.Context, opts EnsureSIMProvisionedOptions) (UIMReadiness, error) {
	return ensureSIMProvisioned(ctx, opts, ensureProvisioningDeps{
		readiness: m.GetUIMReadiness,
		usimAID:   m.GetUSIMAID,
		rebind:    m.UIMRebindPrimaryGWProvisioning,
		sleep:     sleepWithContext,
	})
}

func ensureSIMProvisioned(ctx context.Context, opts EnsureSIMProvisionedOptions, deps ensureProvisioningDeps) (UIMReadiness, error) {
	opts = normalizeEnsureSIMProvisionedOptions(opts)
	var last UIMReadiness
	unknownStreak := 0

	for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
		r, err := deps.readiness(ctx)
		if err != nil {
			return r, err
		}
		last = r

		if r.UIMReady {
			return r, nil // 幂等：已可用，零打扰。
		}
		switch r.Reason {
		case UIMReadinessCardAbsent, UIMReadinessSIMBlocked,
			UIMReadinessTransportFatal, UIMReadinessControlUnavailable:
			return r, nil // 非 provisioning 问题，交回调用方处理。
		}

		activate := false
		switch {
		case r.NeedsProvisioning:
			activate = true
			unknownStreak = 0
		case r.AppState == qmi.UIMAppStateUnknown:
			unknownStreak++
			if unknownStreak >= opts.UnknownAppStateBackstop {
				activate = true
				unknownStreak = 0
			}
		}

		if activate {
			aid, aidErr := deps.usimAID(ctx)
			if aidErr != nil || len(aid) == 0 {
				// 非致命：读不到 AID，降级为旧行为，继续轮询。
			} else if rbErr := deps.rebind(ctx, resolveUIMReloadSlot(r, opts.DefaultSlot), aid); rbErr != nil {
				var nse *qmi.NotSupportedError
				if errors.As(rbErr, &nse) {
					return r, nil // 模组自管理 provisioning，停止尝试。
				}
				// 其他错误非致命，留在 attempt 预算内继续。
			}
		}

		if attempt < opts.MaxAttempts {
			if slErr := deps.sleep(ctx, opts.PollInterval); slErr != nil {
				return last, slErr
			}
		}
	}
	return last, nil // best-effort 穷尽：非致命，由调用方的 ready 门控兜底。
}
