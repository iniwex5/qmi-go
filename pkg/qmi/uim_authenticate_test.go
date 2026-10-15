package qmi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// secretAuthContent is recognisable response content used to prove it never leaks into errors.
var secretAuthContent = []byte{0xDB, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

func authResultTLV(content []byte) TLV {
	value := make([]byte, 2+len(content))
	value[0] = byte(len(content))
	value[1] = byte(len(content) >> 8)
	copy(value[2:], content)
	return TLV{Type: 0x11, Value: value}
}

func assertNoSecretInError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	text := strings.ToUpper(err.Error())
	for _, secret := range []string{"DEADBEEF", "CAFEBABE", "DE AD", "0XDE"} {
		if strings.Contains(text, secret) {
			t.Fatalf("error text leaks response content: %q", err.Error())
		}
	}
}

func TestBuildUIMAuthenticateTLVs(t *testing.T) {
	aid255 := bytes.Repeat([]byte{0xA0}, 255)
	cases := []struct {
		name        string
		sessionType uint8
		aid         []byte
		authContext uint8
		data        []byte
		wantTLVs    []string // "type:value" in order
		wantWire    string   // marshaled TLV bytes
	}{
		{
			name:        "3G security on primary GW provisioning",
			sessionType: UIMSessionTypePrimaryGWProvisioning,
			authContext: UIMAuthContext3GSecurity,
			data:        mustHex(t, "02 AABB 01 CC"),
			wantTLVs:    []string{"01:0000", "02:03 0500 02AABB01CC"},
			wantWire:    "01 0200 0000" + "02 0800 03 0500 02AABB01CC",
		},
		{
			name:        "AID carried in session TLV",
			sessionType: UIMSessionTypeNonProvisioningSlot1,
			aid:         mustHex(t, "A0000000871002"),
			authContext: UIMAuthContextIMSAKASecurity,
			data:        []byte{0x00},
			wantTLVs:    []string{"01:04 07 A0000000871002", "02:0B 0100 00"},
			wantWire:    "01 0900 04 07 A0000000871002" + "02 0400 0B 0100 00",
		},
		{
			name:        "empty data",
			sessionType: UIMSessionTypePrimaryGWProvisioning,
			authContext: UIMAuthContextGSMSecurity,
			wantTLVs:    []string{"01:0000", "02:02 0000"},
			wantWire:    "01 0200 0000" + "02 0300 02 0000",
		},
		{
			name:        "maximum AID length",
			sessionType: UIMSessionTypePrimaryGWProvisioning,
			aid:         aid255,
			authContext: UIMAuthContext3GSecurity,
			data:        []byte{0x01},
			wantTLVs:    []string{"01:00 FF " + hex.EncodeToString(aid255), "02:03 0100 01"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tlvs, err := buildUIMAuthenticateTLVs(tc.sessionType, tc.aid, tc.authContext, tc.data)
			if err != nil {
				t.Fatalf("buildUIMAuthenticateTLVs() error = %v", err)
			}
			if len(tlvs) != len(tc.wantTLVs) {
				t.Fatalf("got %d TLVs, want %d", len(tlvs), len(tc.wantTLVs))
			}
			var wire []byte
			for i, want := range tc.wantTLVs {
				typeStr, valueStr, _ := strings.Cut(want, ":")
				wantType := mustHex(t, typeStr)[0]
				wantValue := mustHex(t, valueStr)
				if tlvs[i].Type != wantType || !bytes.Equal(tlvs[i].Value, wantValue) {
					t.Fatalf("TLV[%d] = %02X:%X, want %02X:%X", i, tlvs[i].Type, tlvs[i].Value, wantType, wantValue)
				}
				if tlvs[i].Type == 0x10 {
					t.Fatal("must not request the response in an indication (TLV 0x10)")
				}
				wire = append(wire, tlvs[i].Marshal()...)
			}
			if tc.wantWire != "" {
				if want := mustHex(t, tc.wantWire); !bytes.Equal(wire, want) {
					t.Fatalf("wire = %X, want %X", wire, want)
				}
			}
		})
	}
}

func TestBuildUIMAuthenticateTLVsCopiesData(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	tlvs, err := buildUIMAuthenticateTLVs(UIMSessionTypePrimaryGWProvisioning, nil, UIMAuthContext3GSecurity, data)
	if err != nil {
		t.Fatalf("buildUIMAuthenticateTLVs() error = %v", err)
	}
	data[0] = 0xFF
	if tlvs[1].Value[3] != 0x01 {
		t.Fatal("request TLV aliases the caller's data slice")
	}
}

func TestBuildUIMAuthenticateTLVsValidatesInputs(t *testing.T) {
	cases := []struct {
		name string
		aid  []byte
		data []byte
		ok   bool
	}{
		{name: "AID 255 bytes", aid: make([]byte, 255), data: []byte{1}, ok: true},
		{name: "AID 256 bytes", aid: make([]byte, 256), data: []byte{1}},
		{name: "largest data that fits the TLV", data: make([]byte, 0xFFFF-3), ok: true},
		{name: "data does not fit the TLV length", data: make([]byte, 0xFFFF-2)},
		{name: "data exceeds u16", data: make([]byte, 0x10000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tlvs, err := buildUIMAuthenticateTLVs(UIMSessionTypePrimaryGWProvisioning, tc.aid, UIMAuthContext3GSecurity, tc.data)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				// The marshaled TLV length must round-trip, i.e. nothing was truncated to u16.
				parsed, _, perr := UnmarshalTLV(tlvs[1].Marshal())
				if perr != nil || len(parsed.Value) != len(tlvs[1].Value) {
					t.Fatalf("data TLV does not round-trip: %v", perr)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseUIMAuthenticateResponseSuccess(t *testing.T) {
	cases := []struct {
		name        string
		tlvs        []TLV
		wantCard    bool
		wantSW      [2]byte
		wantContent []byte
	}{
		{
			name: "with card result",
			tlvs: []TLV{
				successResultTLV(),
				{Type: 0x10, Value: []byte{0x90, 0x00}},
				authResultTLV(secretAuthContent),
			},
			wantCard:    true,
			wantSW:      [2]byte{0x90, 0x00},
			wantContent: secretAuthContent,
		},
		{
			name: "without card result",
			tlvs: []TLV{
				successResultTLV(),
				authResultTLV(secretAuthContent),
			},
			wantContent: secretAuthContent,
		},
		{
			name: "card result reporting a warning status word",
			tlvs: []TLV{
				successResultTLV(),
				{Type: 0x10, Value: []byte{0x61, 0x20}},
				authResultTLV([]byte{0xDC, 0x01, 0x02}),
			},
			wantCard:    true,
			wantSW:      [2]byte{0x61, 0x20},
			wantContent: []byte{0xDC, 0x01, 0x02},
		},
		{
			name: "empty content",
			tlvs: []TLV{
				successResultTLV(),
				authResultTLV(nil),
			},
			wantContent: nil,
		},
		{
			name: "trailing bytes after the declared content are ignored",
			tlvs: []TLV{
				successResultTLV(),
				{Type: 0x11, Value: []byte{0x02, 0x00, 0xAA, 0xBB, 0xCC}},
			},
			wantContent: []byte{0xAA, 0xBB},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUIMAuthenticateResponse(&Packet{TLVs: tc.tlvs})
			if err != nil {
				t.Fatalf("parseUIMAuthenticateResponse() error = %v", err)
			}
			if got.HasCardResult != tc.wantCard || [2]byte{got.SW1, got.SW2} != tc.wantSW {
				t.Fatalf("card result = %v %02X%02X, want %v %X", got.HasCardResult, got.SW1, got.SW2, tc.wantCard, tc.wantSW)
			}
			if !bytes.Equal(got.Data, tc.wantContent) {
				t.Fatalf("Data = %X, want %X", got.Data, tc.wantContent)
			}
		})
	}
}

func TestParseUIMAuthenticateResponseCopiesData(t *testing.T) {
	content := TLV{Type: 0x11, Value: []byte{0x02, 0x00, 0xAA, 0xBB}}
	got, err := parseUIMAuthenticateResponse(&Packet{TLVs: []TLV{successResultTLV(), content}})
	if err != nil {
		t.Fatalf("parseUIMAuthenticateResponse() error = %v", err)
	}
	content.Value[2] = 0x00
	if got.Data[0] != 0xAA {
		t.Fatal("result Data aliases the packet buffer")
	}
}

func TestParseUIMAuthenticateResponseSuccessErrors(t *testing.T) {
	cases := []struct {
		name    string
		tlvs    []TLV
		wantErr string
	}{
		{
			name:    "missing result TLV 0x11",
			tlvs:    []TLV{successResultTLV(), {Type: 0x10, Value: []byte{0x90, 0x00}}},
			wantErr: "authenticate result TLV missing",
		},
		{
			name:    "result TLV 0x11 shorter than its length prefix",
			tlvs:    []TLV{successResultTLV(), {Type: 0x11, Value: []byte{0x0A}}},
			wantErr: "authenticate result TLV missing or too short",
		},
		{
			name:    "result content truncated",
			tlvs:    []TLV{successResultTLV(), {Type: 0x11, Value: []byte{0x0A, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}}},
			wantErr: "authenticate result truncated",
		},
		{
			name: "response deferred to an indication",
			tlvs: []TLV{
				successResultTLV(),
				authResultTLV(secretAuthContent),
				{Type: 0x12, Value: []byte{0x01, 0x00, 0x00, 0x00}},
			},
			wantErr: "deferred to indication",
		},
		{
			name: "deferred response without content",
			tlvs: []TLV{
				successResultTLV(),
				{Type: 0x12, Value: []byte{0x01, 0x00, 0x00, 0x00}},
			},
			wantErr: "deferred to indication",
		},
		{
			name: "truncated card result",
			tlvs: []TLV{
				successResultTLV(),
				{Type: 0x10, Value: []byte{0x90}},
				authResultTLV(secretAuthContent),
			},
			wantErr: "card result TLV too short",
		},
		{
			name:    "missing result TLV 0x02",
			tlvs:    []TLV{authResultTLV(secretAuthContent)},
			wantErr: "missing result TLV",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUIMAuthenticateResponse(&Packet{TLVs: tc.tlvs})
			if err == nil {
				t.Fatalf("expected error, got %+v", got)
			}
			if got != nil {
				t.Fatalf("result = %+v, want nil on error", got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
			assertNoSecretInError(t, err)
		})
	}
}

func TestParseUIMAuthenticateResponseFailures(t *testing.T) {
	cases := []struct {
		name          string
		code          uint16
		extra         []TLV
		wantNotSupp   bool
		wantCardError bool
		wantSW        [2]byte
	}{
		{
			name:          "auth failure with card result 9862",
			code:          0x0003, // internal
			extra:         []TLV{{Type: 0x10, Value: []byte{0x98, 0x62}}},
			wantCardError: true,
			wantSW:        [2]byte{0x98, 0x62},
		},
		{
			name:          "sync failure card result carries through",
			code:          0x0003,
			extra:         []TLV{{Type: 0x10, Value: []byte{0x98, 0x64}}, authResultTLV(secretAuthContent)},
			wantCardError: true,
			wantSW:        [2]byte{0x98, 0x64},
		},
		{
			name: "failure without card result stays a plain QMI error",
			code: 0x0003,
		},
		{
			name:  "truncated card result does not mask the QMI error",
			code:  0x0003,
			extra: []TLV{{Type: 0x10, Value: []byte{0x98}}},
		},
		{
			name:        "not supported",
			code:        QMIErrNotSupported,
			wantNotSupp: true,
		},
		{
			name:        "not supported wins over a card result",
			code:        QMIErrNotSupported,
			extra:       []TLV{{Type: 0x10, Value: []byte{0x98, 0x62}}},
			wantNotSupp: true,
		},
		{
			name:        "invalid QMI command",
			code:        QMIErrInvalidQmiCmd,
			wantNotSupp: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := qmiErrorPacket(tc.code)
			resp.TLVs = append(resp.TLVs, tc.extra...)
			resp.ServiceType = ServiceUIM
			resp.MessageID = UIMAuthenticate

			got, err := parseUIMAuthenticateResponse(resp)
			if err == nil {
				t.Fatalf("expected error, got %+v", got)
			}
			if got != nil {
				t.Fatalf("result = %+v, want nil on error", got)
			}
			assertNoSecretInError(t, err)

			if tc.wantNotSupp {
				nse, ok := err.(*NotSupportedError)
				if !ok {
					t.Fatalf("error = %T %v, want *NotSupportedError", err, err)
				}
				if nse.Operation != "authenticate" {
					t.Fatalf("Operation = %q, want authenticate", nse.Operation)
				}
				return
			}

			var ce *UIMCardError
			if gotCE := errors.As(err, &ce); gotCE != tc.wantCardError {
				t.Fatalf("errors.As(*UIMCardError) = %v, want %v (err=%v)", gotCE, tc.wantCardError, err)
			}
			qe := GetQMIError(err)
			if qe == nil || qe.ErrorCode != tc.code || qe.Service != ServiceUIM || qe.MessageID != UIMAuthenticate {
				t.Fatalf("GetQMIError() = %+v, want error code 0x%04X for UIM Authenticate", qe, tc.code)
			}
			if !tc.wantCardError {
				if _, ok := err.(*QMIError); !ok {
					t.Fatalf("error = %T, want the bare *QMIError", err)
				}
				return
			}
			if ce.Operation != "authenticate" {
				t.Fatalf("Operation = %q, want authenticate", ce.Operation)
			}
			sw1, sw2 := ce.UIMStatusWord()
			if [2]byte{sw1, sw2} != tc.wantSW {
				t.Fatalf("UIMStatusWord() = %02X%02X, want %X", sw1, sw2, tc.wantSW)
			}
		})
	}
}

func TestUIMCardError(t *testing.T) {
	qe := &QMIError{Service: ServiceUIM, MessageID: UIMOpenLogicalChannel, Result: 1, ErrorCode: 0x0003}
	err := &UIMCardError{Operation: "open logical channel", SW1: 0x6A, SW2: 0x81, Err: qe}

	if want := "open logical channel: card SW=6A81: " + qe.Error(); err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	if errors.Unwrap(err) != qe {
		t.Fatal("Unwrap() did not return the underlying error")
	}
	if got := (&UIMCardError{Operation: "authenticate", SW1: 0x01, SW2: 0x0A}).Error(); got != "authenticate: card SW=010A" {
		t.Fatalf("Error() without Err = %q", got)
	}

	// The cross-repo contract: detectable through a local interface, also through further wrapping.
	type statusWord interface{ UIMStatusWord() (sw1, sw2 byte) }
	wrapped := fmt.Errorf("manager: %w", err)
	var sw statusWord
	if !errors.As(wrapped, &sw) {
		t.Fatal("errors.As to a UIMStatusWord interface failed")
	}
	if sw1, sw2 := sw.UIMStatusWord(); sw1 != 0x6A || sw2 != 0x81 {
		t.Fatalf("UIMStatusWord() = %02X%02X, want 6A81", sw1, sw2)
	}
	if !IsQMIError(wrapped) || GetQMIError(wrapped) != qe {
		t.Fatal("the wrapped *QMIError is no longer reachable")
	}
}

func TestParseOpenLogicalChannelResponse(t *testing.T) {
	cases := []struct {
		name        string
		tlvs        []TLV
		wantChannel byte
		wantErr     bool
		wantParse   bool // a response-format error, not a QMI failure
		wantNotSupp bool
		wantSW      *[2]byte
		wantCode    uint16
	}{
		{
			name:        "success",
			tlvs:        []TLV{successResultTLV(), {Type: 0x10, Value: []byte{0x02}}},
			wantChannel: 2,
		},
		{
			name:        "success ignores a card result",
			tlvs:        []TLV{successResultTLV(), {Type: 0x10, Value: []byte{0x03}}, {Type: 0x11, Value: []byte{0x90, 0x00}}},
			wantChannel: 3,
		},
		{
			name:      "success without channel id",
			tlvs:      []TLV{successResultTLV()},
			wantErr:   true,
			wantParse: true,
		},
		{
			name:     "failure with card result 6A81",
			tlvs:     []TLV{qmiErrorResultTLV(0x0003), {Type: 0x11, Value: []byte{0x6A, 0x81}}},
			wantErr:  true,
			wantSW:   &[2]byte{0x6A, 0x81},
			wantCode: 0x0003,
		},
		{
			name:     "failure with card result 6A82",
			tlvs:     []TLV{qmiErrorResultTLV(0x0003), {Type: 0x11, Value: []byte{0x6A, 0x82}}, {Type: 0x12, Value: []byte{0x00}}},
			wantErr:  true,
			wantSW:   &[2]byte{0x6A, 0x82},
			wantCode: 0x0003,
		},
		{
			name:     "failure without card result",
			tlvs:     []TLV{qmiErrorResultTLV(0x0003)},
			wantErr:  true,
			wantCode: 0x0003,
		},
		{
			name:     "failure with truncated card result",
			tlvs:     []TLV{qmiErrorResultTLV(0x0003), {Type: 0x11, Value: []byte{0x6A}}},
			wantErr:  true,
			wantCode: 0x0003,
		},
		{
			name:        "not supported stays unchanged",
			tlvs:        []TLV{qmiErrorResultTLV(QMIErrNotSupported), {Type: 0x11, Value: []byte{0x6A, 0x81}}},
			wantErr:     true,
			wantNotSupp: true,
		},
		{
			name:        "invalid QMI command stays unchanged",
			tlvs:        []TLV{qmiErrorResultTLV(QMIErrInvalidQmiCmd)},
			wantErr:     true,
			wantNotSupp: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &Packet{ServiceType: ServiceUIM, MessageID: UIMOpenLogicalChannel, TLVs: tc.tlvs}
			channel, err := parseOpenLogicalChannelResponse(resp)
			if !tc.wantErr {
				if err != nil || channel != tc.wantChannel {
					t.Fatalf("channel, err = %d, %v, want %d, nil", channel, err, tc.wantChannel)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.wantParse {
				if IsQMIError(err) {
					t.Fatalf("error = %v, want a response-format error", err)
				}
				return
			}
			if tc.wantNotSupp {
				nse, ok := err.(*NotSupportedError)
				if !ok || nse.Operation != "open logical channel" {
					t.Fatalf("error = %T %v, want unchanged *NotSupportedError", err, err)
				}
				return
			}
			var ce *UIMCardError
			if gotCE := errors.As(err, &ce); gotCE != (tc.wantSW != nil) {
				t.Fatalf("errors.As(*UIMCardError) = %v, want %v (err=%v)", gotCE, tc.wantSW != nil, err)
			}
			qe := GetQMIError(err)
			if qe == nil || qe.ErrorCode != tc.wantCode {
				t.Fatalf("GetQMIError() = %+v, want error code 0x%04X", qe, tc.wantCode)
			}
			if tc.wantSW == nil {
				if _, ok := err.(*QMIError); !ok {
					t.Fatalf("error = %T, want the bare *QMIError", err)
				}
				return
			}
			if ce.Operation != "open logical channel" {
				t.Fatalf("Operation = %q", ce.Operation)
			}
			sw1, sw2 := ce.UIMStatusWord()
			if [2]byte{sw1, sw2} != *tc.wantSW {
				t.Fatalf("UIMStatusWord() = %02X%02X, want %X", sw1, sw2, *tc.wantSW)
			}
			wantText := fmt.Sprintf("open logical channel: card SW=%02X%02X: ", tc.wantSW[0], tc.wantSW[1])
			if !strings.HasPrefix(err.Error(), wantText) {
				t.Fatalf("Error() = %q, want prefix %q", err.Error(), wantText)
			}
		})
	}
}

func TestUIMServiceAuthenticate(t *testing.T) {
	t.Run("request and success response", func(t *testing.T) {
		c := newUIMUnitTestClient()
		u := &UIMService{client: c, clientID: 5}
		data := mustHex(t, "02 AABB 01 CC")
		var seen *Packet
		defer serveUIMUnitTestRequests(t, c, func(req *Packet) *Packet {
			seen = req
			return &Packet{TLVs: []TLV{
				successResultTLV(),
				{Type: 0x10, Value: []byte{0x90, 0x00}},
				authResultTLV(secretAuthContent),
			}}
		})()

		got, err := u.Authenticate(context.Background(), UIMSessionTypePrimaryGWProvisioning, nil, UIMAuthContext3GSecurity, data)
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if seen == nil || seen.ServiceType != ServiceUIM || seen.MessageID != UIMAuthenticate || seen.ClientID != 5 {
			t.Fatalf("unexpected request: %+v", seen)
		}
		if len(seen.TLVs) != 2 {
			t.Fatalf("request has %d TLVs, want 2", len(seen.TLVs))
		}
		if tlv := FindTLV(seen.TLVs, 0x01); tlv == nil || !bytes.Equal(tlv.Value, []byte{0x00, 0x00}) {
			t.Fatalf("session TLV = %+v", tlv)
		}
		if tlv := FindTLV(seen.TLVs, 0x02); tlv == nil || !bytes.Equal(tlv.Value, mustHex(t, "03 0500 02AABB01CC")) {
			t.Fatalf("authentication data TLV = %+v", tlv)
		}
		if FindTLV(seen.TLVs, 0x10) != nil {
			t.Fatal("request must not carry the response-in-indication TLV")
		}
		if !got.HasCardResult || got.SW1 != 0x90 || got.SW2 != 0x00 || !bytes.Equal(got.Data, secretAuthContent) {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("card failure", func(t *testing.T) {
		c := newUIMUnitTestClient()
		u := &UIMService{client: c, clientID: 5}
		defer serveUIMUnitTestRequests(t, c, func(req *Packet) *Packet {
			resp := qmiErrorPacket(0x0003)
			resp.TLVs = append(resp.TLVs, TLV{Type: 0x10, Value: []byte{0x98, 0x62}})
			return resp
		})()

		got, err := u.Authenticate(context.Background(), UIMSessionTypePrimaryGWProvisioning, nil, UIMAuthContext3GSecurity, []byte{0x00})
		if got != nil {
			t.Fatalf("result = %+v, want nil", got)
		}
		var ce *UIMCardError
		if !errors.As(err, &ce) {
			t.Fatalf("error = %T %v, want *UIMCardError", err, err)
		}
		if sw1, sw2 := ce.UIMStatusWord(); sw1 != 0x98 || sw2 != 0x62 {
			t.Fatalf("UIMStatusWord() = %02X%02X, want 9862", sw1, sw2)
		}
		if !IsQMIError(err) {
			t.Fatal("wrapped *QMIError is not reachable")
		}
	})

	t.Run("not supported", func(t *testing.T) {
		c := newUIMUnitTestClient()
		u := &UIMService{client: c, clientID: 5}
		defer serveUIMUnitTestRequests(t, c, func(req *Packet) *Packet {
			return qmiErrorPacket(QMIErrInvalidQmiCmd)
		})()

		_, err := u.Authenticate(context.Background(), UIMSessionTypePrimaryGWProvisioning, nil, UIMAuthContext3GSecurity, []byte{0x00})
		if _, ok := err.(*NotSupportedError); !ok {
			t.Fatalf("error = %T %v, want *NotSupportedError", err, err)
		}
	})

	t.Run("invalid input is rejected before sending", func(t *testing.T) {
		c := newUIMUnitTestClient()
		u := &UIMService{client: c, clientID: 5}
		_, err := u.Authenticate(context.Background(), UIMSessionTypePrimaryGWProvisioning, make([]byte, 256), UIMAuthContext3GSecurity, []byte{0x00})
		if err == nil {
			t.Fatal("expected error for oversized AID")
		}
		select {
		case <-c.writeCh:
			t.Fatal("a request was sent despite invalid input")
		default:
		}
	})
}
