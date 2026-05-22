package manager

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/iniwex5/quectel-qmi-go/pkg/qmi"
)

func TestAllocateServicesUsesCallerContextForClientIDAllocation(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg = Config{EnableIPv4: true}
	m.client = &qmi.Client{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	wdsCalls := 0
	nasCalls := 0
	m.newWDSService = func(ctx context.Context, _ *qmi.Client) (*qmi.WDSService, error) {
		wdsCalls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("WDS allocation context has no deadline")
		}
		return nil, context.DeadlineExceeded
	}
	m.newNASService = func(context.Context, *qmi.Client) (*qmi.NASService, error) {
		nasCalls++
		return &qmi.NASService{}, nil
	}

	err := m.allocateServices(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("allocateServices() err=%v, want context.DeadlineExceeded", err)
	}
	if wdsCalls != 1 {
		t.Fatalf("WDS allocations=%d want 1", wdsCalls)
	}
	if nasCalls != 0 {
		t.Fatalf("NAS allocations=%d want 0 after WDS context cancellation", nasCalls)
	}
}

func TestAllocateServicesSkipsWMSAndWDAWhenDisabledButKeepsVOICE(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg = Config{
		Device:          ModemDevice{NetInterface: ""},
		EnableIPv4:      false,
		EnableIPv6:      false,
		DisableWMSInd:   true,
		DisableVOICEInd: true,
	}
	m.client = &qmi.Client{}

	m.newNASService = func(context.Context, *qmi.Client) (*qmi.NASService, error) {
		return nil, fmt.Errorf("NAS unavailable")
	}
	m.newDMSService = func(context.Context, *qmi.Client) (*qmi.DMSService, error) {
		return nil, fmt.Errorf("DMS unavailable")
	}
	m.newUIMService = func(context.Context, *qmi.Client) (*qmi.UIMService, error) {
		return nil, fmt.Errorf("UIM unavailable")
	}

	wdaCalls := 0
	wmsCalls := 0
	voiceCalls := 0
	m.newWDAService = func(context.Context, *qmi.Client) (*qmi.WDAService, error) {
		wdaCalls++
		return &qmi.WDAService{}, nil
	}
	m.newWMSService = func(context.Context, *qmi.Client) (*qmi.WMSService, error) {
		wmsCalls++
		return &qmi.WMSService{}, nil
	}
	m.newVOICEService = func(context.Context, *qmi.Client) (*qmi.VOICEService, error) {
		voiceCalls++
		return &qmi.VOICEService{}, nil
	}

	if err := m.allocateServices(context.Background()); err != nil {
		t.Fatalf("allocateServices() unexpected error: %v", err)
	}
	if wdaCalls != 0 {
		t.Fatalf("WDA allocations=%d want 0 without data interface/family", wdaCalls)
	}
	if wmsCalls != 0 {
		t.Fatalf("WMS allocations=%d want 0 when WMS indications are disabled", wmsCalls)
	}
	if voiceCalls != 1 {
		t.Fatalf("VOICE allocations=%d want 1", voiceCalls)
	}
}

func TestAllocateServicesLazyDataPlaneSkipsWDSAndWDAButKeepsVOICE(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg = Config{
		Device:          ModemDevice{NetInterface: "wwan0"},
		EnableIPv4:      true,
		EnableIPv6:      false,
		DisableWMSInd:   true,
		DisableVOICEInd: true,
		DataPlanePolicy: DataPlanePolicyLazy,
	}
	m.client = &qmi.Client{}

	wdsCalls := 0
	wdaCalls := 0
	voiceCalls := 0
	m.newWDSService = func(context.Context, *qmi.Client) (*qmi.WDSService, error) {
		wdsCalls++
		return &qmi.WDSService{}, nil
	}
	m.newWDAService = func(context.Context, *qmi.Client) (*qmi.WDAService, error) {
		wdaCalls++
		return &qmi.WDAService{}, nil
	}
	m.newNASService = func(context.Context, *qmi.Client) (*qmi.NASService, error) {
		return nil, fmt.Errorf("NAS unavailable")
	}
	m.newDMSService = func(context.Context, *qmi.Client) (*qmi.DMSService, error) {
		return nil, fmt.Errorf("DMS unavailable")
	}
	m.newUIMService = func(context.Context, *qmi.Client) (*qmi.UIMService, error) {
		return nil, fmt.Errorf("UIM unavailable")
	}
	m.newVOICEService = func(context.Context, *qmi.Client) (*qmi.VOICEService, error) {
		voiceCalls++
		return &qmi.VOICEService{}, nil
	}

	if err := m.allocateServices(context.Background()); err != nil {
		t.Fatalf("allocateServices() error = %v", err)
	}
	if wdsCalls != 0 || wdaCalls != 0 {
		t.Fatalf("data-plane allocations WDS=%d WDA=%d want 0/0", wdsCalls, wdaCalls)
	}
	if voiceCalls != 1 {
		t.Fatalf("VOICE allocations=%d want 1", voiceCalls)
	}
}

func TestEnsureDataPlaneServicesAllocatesLazyServices(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg = Config{
		Device:          ModemDevice{NetInterface: "wwan0"},
		EnableIPv4:      true,
		DataPlanePolicy: DataPlanePolicyLazy,
	}
	m.client = &qmi.Client{}

	wdsCalls := 0
	wdaCalls := 0
	rawIPCalls := 0
	m.newWDSService = func(context.Context, *qmi.Client) (*qmi.WDSService, error) {
		wdsCalls++
		return &qmi.WDSService{}, nil
	}
	m.newWDAService = func(context.Context, *qmi.Client) (*qmi.WDAService, error) {
		wdaCalls++
		return &qmi.WDAService{}, nil
	}
	m.enableRawIPHook = func(context.Context) error {
		rawIPCalls++
		return nil
	}

	if err := m.ensureDataPlaneServices(context.Background()); err != nil {
		t.Fatalf("ensureDataPlaneServices() error = %v", err)
	}
	if wdsCalls != 1 || wdaCalls != 1 {
		t.Fatalf("data-plane allocations WDS=%d WDA=%d want 1/1", wdsCalls, wdaCalls)
	}
	if rawIPCalls != 1 {
		t.Fatalf("RawIP calls=%d want 1", rawIPCalls)
	}
}
