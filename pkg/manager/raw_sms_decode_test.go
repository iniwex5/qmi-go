package manager

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecodeIncomingSMSPDUDecodesStoredPDUWithSMSCHeader(t *testing.T) {
	raw, err := hex.DecodeString(fixedSlotPaddedRawPDU)
	if err != nil {
		t.Fatal(err)
	}

	sms, err := DecodeIncomingSMSPDU(raw, 1, 7)
	if err != nil {
		t.Fatalf("DecodeIncomingSMSPDU() error = %v", err)
	}
	if sms.Index != 7 || sms.Storage != 1 {
		t.Fatalf("index/storage=%d/%d, want 7/1", sms.Index, sms.Storage)
	}
	if strings.TrimSpace(sms.Sender) == "" {
		t.Fatal("sender is empty")
	}
	if strings.TrimSpace(sms.Message) == "" {
		t.Fatal("message is empty")
	}
}

func TestDecodeIncomingSMSPDUDecodesDirectTPDU(t *testing.T) {
	raw, err := hex.DecodeString(fixedSlotPaddedRawPDU)
	if err != nil {
		t.Fatal(err)
	}
	smscLen := int(raw[0])
	tpdu := raw[1+smscLen:]

	sms, err := DecodeIncomingSMSPDU(tpdu, 0xff, ^uint32(0))
	if err != nil {
		t.Fatalf("DecodeIncomingSMSPDU() error = %v", err)
	}
	if strings.TrimSpace(sms.Sender) == "" {
		t.Fatal("sender is empty")
	}
	if strings.TrimSpace(sms.Message) == "" {
		t.Fatal("message is empty")
	}
}
