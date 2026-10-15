package manager

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iniwex5/qmi-go/pkg/qmi"
)

func TestSendAPDUUsesStopTimeoutForLegacyMethod(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg.Timeouts.Stop = 25 * time.Millisecond
	var gotDeadline time.Time
	m.sendAPDUHook = func(ctx context.Context, slot uint8, channel uint8, command []byte) ([]byte, error) {
		var ok bool
		gotDeadline, ok = ctx.Deadline()
		if !ok {
			t.Fatal("SendAPDU hook ctx has no deadline")
		}
		return []byte{0x90, 0x00}, nil
	}

	if _, err := m.SendAPDU(1, 2, []byte{0x80, 0xE2}); err != nil {
		t.Fatalf("SendAPDU() error = %v", err)
	}
	remaining := time.Until(gotDeadline)
	if remaining <= 0 || remaining > 100*time.Millisecond {
		t.Fatalf("SendAPDU deadline remaining = %s, want close to Stop timeout", remaining)
	}
}

func TestSendAPDUContextPreservesCallerDeadline(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg.Timeouts.Stop = 25 * time.Millisecond
	callerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wantDeadline, _ := callerCtx.Deadline()
	var gotDeadline time.Time
	m.sendAPDUHook = func(ctx context.Context, slot uint8, channel uint8, command []byte) ([]byte, error) {
		var ok bool
		gotDeadline, ok = ctx.Deadline()
		if !ok {
			t.Fatal("SendAPDUContext hook ctx has no deadline")
		}
		return []byte{0x90, 0x00}, nil
	}

	if _, err := m.SendAPDUContext(callerCtx, 1, 2, []byte{0x80, 0xE2}); err != nil {
		t.Fatalf("SendAPDUContext() error = %v", err)
	}
	if !gotDeadline.Equal(wantDeadline) {
		t.Fatalf("SendAPDUContext deadline = %s, want caller deadline %s", gotDeadline, wantDeadline)
	}
}

func TestOpenLogicalChannelContextPreservesCallerDeadline(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg.Timeouts.Stop = 25 * time.Millisecond
	callerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wantDeadline, _ := callerCtx.Deadline()
	var gotDeadline time.Time
	m.openLogicalChannelHook = func(ctx context.Context, slot uint8, aid []byte) (byte, error) {
		var ok bool
		gotDeadline, ok = ctx.Deadline()
		if !ok {
			t.Fatal("OpenLogicalChannelContext hook ctx has no deadline")
		}
		return 2, nil
	}

	if _, err := m.OpenLogicalChannelContext(callerCtx, 1, []byte{0xA0, 0x00}); err != nil {
		t.Fatalf("OpenLogicalChannelContext() error = %v", err)
	}
	if !gotDeadline.Equal(wantDeadline) {
		t.Fatalf("OpenLogicalChannelContext deadline = %s, want caller deadline %s", gotDeadline, wantDeadline)
	}
}

func TestCloseLogicalChannelContextPreservesCallerDeadline(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg.Timeouts.Stop = 25 * time.Millisecond
	callerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wantDeadline, _ := callerCtx.Deadline()
	var gotDeadline time.Time
	m.closeLogicalChannelHook = func(ctx context.Context, slot uint8, channel uint8) error {
		var ok bool
		gotDeadline, ok = ctx.Deadline()
		if !ok {
			t.Fatal("CloseLogicalChannelContext hook ctx has no deadline")
		}
		return nil
	}

	if err := m.CloseLogicalChannelContext(callerCtx, 1, 2); err != nil {
		t.Fatalf("CloseLogicalChannelContext() error = %v", err)
	}
	if !gotDeadline.Equal(wantDeadline) {
		t.Fatalf("CloseLogicalChannelContext deadline = %s, want caller deadline %s", gotDeadline, wantDeadline)
	}
}

func TestUIMAuthenticateContextPreservesCallerDeadlineAndArguments(t *testing.T) {
	m := newRecoveryTestManager()
	m.cfg.Timeouts.Stop = 25 * time.Millisecond
	callerCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wantDeadline, _ := callerCtx.Deadline()
	wantAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}
	wantData := []byte{0x10, 0x01, 0x02}
	want := &qmi.UIMAuthenticateResult{HasCardResult: true, SW1: 0x90, Data: []byte{0xDB, 0x00}}
	var gotDeadline time.Time
	m.uimAuthenticateHook = func(ctx context.Context, sessionType uint8, aid []byte, authContext uint8, data []byte) (*qmi.UIMAuthenticateResult, error) {
		var ok bool
		gotDeadline, ok = ctx.Deadline()
		if !ok {
			t.Fatal("UIMAuthenticateContext hook ctx has no deadline")
		}
		if sessionType != qmi.UIMSessionTypePrimaryGWProvisioning || authContext != qmi.UIMAuthContext3GSecurity ||
			!bytes.Equal(aid, wantAID) || !bytes.Equal(data, wantData) {
			t.Fatalf("hook args = %d %X %d %X", sessionType, aid, authContext, data)
		}
		return want, nil
	}

	got, err := m.UIMAuthenticateContext(callerCtx, qmi.UIMSessionTypePrimaryGWProvisioning, wantAID, qmi.UIMAuthContext3GSecurity, wantData)
	if err != nil {
		t.Fatalf("UIMAuthenticateContext() error = %v", err)
	}
	if got != want {
		t.Fatalf("UIMAuthenticateContext() = %+v, want %+v", got, want)
	}
	if !gotDeadline.Equal(wantDeadline) {
		t.Fatalf("UIMAuthenticateContext deadline = %s, want caller deadline %s", gotDeadline, wantDeadline)
	}
}

func TestUIMAuthenticateContextKeepsCardErrorReachable(t *testing.T) {
	m := newRecoveryTestManager()
	qe := &qmi.QMIError{Service: qmi.ServiceUIM, MessageID: qmi.UIMAuthenticate, Result: 1, ErrorCode: qmi.QMIErrInternal}
	m.uimAuthenticateHook = func(context.Context, uint8, []byte, uint8, []byte) (*qmi.UIMAuthenticateResult, error) {
		return nil, &qmi.UIMCardError{Operation: "authenticate", SW1: 0x98, SW2: 0x62, Err: qe}
	}

	got, err := m.UIMAuthenticateContext(context.Background(), qmi.UIMSessionTypePrimaryGWProvisioning, nil, qmi.UIMAuthContext3GSecurity, []byte{0x00})
	if got != nil {
		t.Fatalf("result = %+v, want nil", got)
	}
	var sw interface{ UIMStatusWord() (sw1, sw2 byte) }
	if !errors.As(err, &sw) {
		t.Fatalf("error %v does not expose UIMStatusWord", err)
	}
	if sw1, sw2 := sw.UIMStatusWord(); sw1 != 0x98 || sw2 != 0x62 {
		t.Fatalf("UIMStatusWord() = %02X%02X, want 9862", sw1, sw2)
	}
	if !errors.Is(err, qe) {
		t.Fatal("underlying *QMIError is not reachable")
	}
}

func TestUIMCardErrorKeepsServiceRecoveryClassification(t *testing.T) {
	cases := []struct {
		name string
		code uint16
		want bool
	}{
		{name: "card failure without recoverable QMI code", code: qmi.QMIErrInternal, want: false},
		{name: "device not ready is still recoverable", code: qmi.QMIErrDeviceNotReady, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &qmi.UIMCardError{
				Operation: "open logical channel", SW1: 0x6A, SW2: 0x81,
				Err: &qmi.QMIError{Service: qmi.ServiceUIM, MessageID: qmi.UIMOpenLogicalChannel, Result: 1, ErrorCode: tc.code},
			}
			if got := shouldRecoverServiceError("UIM", err, "uim service not available"); got != tc.want {
				t.Fatalf("shouldRecoverServiceError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUIMAuthenticateResendGuardOnlyResendsWhenCardNeverReached(t *testing.T) {
	cases := []struct {
		name       string
		first      error
		wantResend bool
	}{
		{name: "service not ready", first: &ServiceNotReadyError{Service: "UIM"}, wantResend: true},
		{name: "device not ready without card result", first: &qmi.QMIError{Service: qmi.ServiceUIM, MessageID: qmi.UIMAuthenticate, Result: 1, ErrorCode: qmi.QMIErrDeviceNotReady}, wantResend: true},
		{name: "deadline exceeded", first: context.DeadlineExceeded, wantResend: false},
		{name: "card status word", first: &qmi.UIMCardError{Operation: "authenticate", SW1: 0x98, SW2: 0x62, Err: &qmi.QMIError{ErrorCode: qmi.QMIErrDeviceNotReady}}, wantResend: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			guarded := uimAuthenticateResendGuard(func(*qmi.UIMService) (*qmi.UIMAuthenticateResult, error) {
				calls++
				if calls == 1 {
					return nil, tc.first
				}
				return &qmi.UIMAuthenticateResult{}, nil
			})
			if _, err := guarded(nil); !errors.Is(err, tc.first) {
				t.Fatalf("first call error = %v, want %v", err, tc.first)
			}
			_, err := guarded(nil)
			if tc.wantResend {
				if calls != 2 || err != nil {
					t.Fatalf("resend: calls=%d err=%v, want 2 calls and success", calls, err)
				}
				return
			}
			if calls != 1 || !errors.Is(err, tc.first) {
				t.Fatalf("no resend: calls=%d err=%v, want 1 call and the first error", calls, err)
			}
		})
	}
}
