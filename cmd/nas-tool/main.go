package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/iniwex5/qmi-go/pkg/qmi"
)

func main() {
	devicePath := flag.String("device", defaultQmiDevice(), "Path to QMI device")
	action := flag.String("action", "all", "Action: all, serving, signal, signal-info, sysinfo, scan, register, cell-info, dump")
	useQRTR := flag.Bool("qrtr", false, "Use native QRTR (AF_QIPCRTR) transport instead of a cdc-wdm device")
	flag.Parse()

	client, err := qmi.NewClientWithOptions(context.Background(), *devicePath, qmi.ClientOptions{UseQRTR: *useQRTR})
	if err != nil {
		log.Fatalf("Failed to create QMI client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nas, err := qmi.NewNASService(client)
	if err != nil {
		log.Fatalf("Failed to create NAS service: %v", err)
	}
	defer nas.Close()

	switch *action {
	case "all":
		runRegister(nas)
		runServing(ctx, nas)
		runSignal(ctx, nas)
		runSignalInfo(ctx, nas)
		runSysInfo(ctx, nas)
		runScan(nas)
		runCellLocationInfo(ctx, nas)
	case "serving":
		runServing(ctx, nas)
	case "signal":
		runSignal(ctx, nas)
	case "signal-info":
		runSignalInfo(ctx, nas)
	case "sysinfo":
		runSysInfo(ctx, nas)
	case "scan":
		runScan(nas)
	case "register":
		runRegister(nas)
	case "cell-info":
		runCellLocationInfo(ctx, nas)
	case "dump":
		runDump(ctx, client, nas)
	default:
		log.Fatalf("Unknown action: %s", *action)
	}
}

func runRegister(nas *qmi.NASService) {
	fmt.Println("=== NAS Register Indications ===")
	if err := nas.RegisterIndications(); err != nil {
		log.Printf("RegisterIndications failed: %v", err)
		return
	}
	fmt.Println("OK")
	fmt.Println()
}

func runServing(ctx context.Context, nas *qmi.NASService) {
	fmt.Println("=== NAS Serving System ===")
	ss, err := nas.GetServingSystem(ctx)
	if err != nil {
		log.Printf("GetServingSystem failed: %v", err)
		return
	}
	fmt.Printf("Registration: %s (%d)\n", ss.RegistrationState.String(), ss.RegistrationState)
	fmt.Printf("PSAttached: %v\n", ss.PSAttached)
	fmt.Printf("RadioInterface: %d\n", ss.RadioInterface)
	fmt.Printf("MCC: %d\n", ss.MCC)
	fmt.Printf("MNC: %d\n", ss.MNC)
	fmt.Println()
}

func runSignal(ctx context.Context, nas *qmi.NASService) {
	fmt.Println("=== NAS Signal Strength ===")
	s, err := nas.GetSignalStrength(ctx)
	if err != nil {
		log.Printf("GetSignalStrength failed: %v", err)
		return
	}
	fmt.Printf("RSSI: %d\n", s.RSSI)
	fmt.Printf("RSRQ: %d\n", s.RSRQ)
	fmt.Printf("RSRP: %d\n", s.RSRP)
	fmt.Printf("ECIO: %d\n", s.ECIO)
	fmt.Printf("SNR: %d\n", s.SNR)
	fmt.Println()
}

func runSignalInfo(ctx context.Context, nas *qmi.NASService) {
	fmt.Println("=== NAS Signal Info ===")
	info, err := nas.GetSignalInfo(ctx)
	if err != nil {
		log.Printf("GetSignalInfo failed: %v", err)
		return
	}
	fmt.Printf("LTE RSRP: %d\n", info.LTERSRP)
	fmt.Printf("LTE RSRQ: %d\n", info.LTERSRQ)
	fmt.Printf("LTE RSSNR: %d\n", info.LTERSSNR)
	fmt.Printf("NR5G RSRP: %d\n", info.NR5GRSRP)
	fmt.Printf("NR5G RSRQ: %d\n", info.NR5GRSRQ)
	fmt.Printf("NR5G SINR: %d\n", info.NR5GSINR)
	fmt.Println()
}

func runSysInfo(ctx context.Context, nas *qmi.NASService) {
	fmt.Println("=== NAS Sys Info ===")
	info, err := nas.GetSysInfo(ctx)
	if err != nil {
		log.Printf("GetSysInfo failed: %v", err)
		return
	}
	fmt.Printf("CellID: %d\n", info.CellID)
	fmt.Printf("TAC: %d\n", info.TAC)
	fmt.Printf("LAC: %d\n", info.LAC)
	fmt.Println()
}

func runScan(nas *qmi.NASService) {
	fmt.Println("=== NAS Network Scan ===")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := nas.PerformNetworkScan(ctx)
	if err != nil {
		log.Printf("PerformNetworkScan failed: %v", err)
		return
	}
	for _, r := range res {
		fmt.Printf("PLMN: %s-%s status=%d rats=%v desc=%q\n", r.MCC, r.MNC, r.Status, r.RATs, r.Description)
	}
	fmt.Println()
}

func runCellLocationInfo(ctx context.Context, nas *qmi.NASService) {
	fmt.Println("=== NAS Cell Location Info ===")
	info, err := nas.GetCellLocationInfo(ctx)
	if err != nil {
		log.Printf("GetCellLocationInfo failed: %v", err)
		return
	}

	if info.LTE != nil {
		fmt.Println("LTE serving:")
		fmt.Printf("  UE in idle: %v\n", info.LTE.UEInIdle)
		fmt.Printf("  PLMN: %s-%s\n", info.LTE.MCC, info.LTE.MNC)
		fmt.Printf("  TAC: %d  GlobalCellID: %d (0x%x)\n", info.LTE.TAC, info.LTE.GlobalCellID, info.LTE.GlobalCellID)
		fmt.Printf("  EARFCN: %d  ServingCellID: %d\n", info.LTE.EARFCN, info.LTE.ServingCellID)
		fmt.Printf("  CellReselectionPriority: %d\n", info.LTE.CellReselectionPriority)
		if info.LTE.HasIdleThresholds {
			fmt.Printf("  Snonintra/ServingLow/Sintra: %d/%d/%d\n",
				info.LTE.SNonIntraSearchThreshold,
				info.LTE.ServingCellLowThreshold,
				info.LTE.SIntraSearchThreshold)
		}
		if info.LTE.HasTimingAdvance {
			fmt.Printf("  TimingAdvance: %d\n", info.LTE.TimingAdvance)
		}
		if len(info.LTE.IntraFrequencyNeighbors) > 0 {
			fmt.Printf("  Intra-frequency neighbors (%d):\n", len(info.LTE.IntraFrequencyNeighbors))
			for i, c := range info.LTE.IntraFrequencyNeighbors {
				fmt.Printf("    [%d] PCI=%d RSRQ=%.1f RSRP=%.1f RSSI=%.1f RX=%d\n",
					i, c.PhysicalCellID,
					float64(c.RSRQ)/10.0,
					float64(c.RSRP)/10.0,
					float64(c.RSSI)/10.0,
					c.CellSelectionRXLevel)
			}
		}
		if len(info.LTE.InterFrequencyNeighbors) > 0 {
			fmt.Printf("  Inter-frequency entries (%d):\n", len(info.LTE.InterFrequencyNeighbors))
			for i, freq := range info.LTE.InterFrequencyNeighbors {
				fmt.Printf("    [%d] EARFCN=%d Low/High=%d/%d", i, freq.EARFCN,
					freq.CellSelectionRXLevelLow, freq.CellSelectionRXLevelHigh)
				if freq.HasCellReselectionPriority {
					fmt.Printf(" Priority=%d", freq.CellReselectionPriority)
				}
				fmt.Printf(" Neighbors=%d\n", len(freq.Neighbors))
				for j, c := range freq.Neighbors {
					fmt.Printf("      [%d] PCI=%d RSRQ=%.1f RSRP=%.1f RSSI=%.1f RX=%d\n",
						j, c.PhysicalCellID,
						float64(c.RSRQ)/10.0,
						float64(c.RSRP)/10.0,
						float64(c.RSSI)/10.0,
						c.CellSelectionRXLevel)
				}
			}
		}
	}
	if info.NR5G != nil {
		fmt.Println("NR5G serving:")
		fmt.Printf("  PLMN: %s-%s\n", info.NR5G.MCC, info.NR5G.MNC)
		fmt.Printf("  TAC: %d  GlobalCellID: %d (0x%x)\n", info.NR5G.TAC, info.NR5G.GlobalCellID, info.NR5G.GlobalCellID)
		fmt.Printf("  PhysicalCellID: %d\n", info.NR5G.PhysicalCellID)
		fmt.Printf("  RSRQ: %.1f  RSRP: %.1f  SNR: %.1f\n",
			float64(info.NR5G.RSRQ)/10.0,
			float64(info.NR5G.RSRP)/10.0,
			float64(info.NR5G.SNR)/10.0)
		if info.NR5G.HasARFCN {
			fmt.Printf("  ARFCN: %d\n", info.NR5G.ARFCN)
		}
	}
	fmt.Println()
}

func runDump(ctx context.Context, client *qmi.Client, nas *qmi.NASService) {
	fmt.Println("=== NAS Dump TLVs ===")

	type item struct {
		name   string
		msgID  uint16
		client uint8
	}

	items := []item{
		{name: "NASGetServingSystem", msgID: qmi.NASGetServingSystem, client: nas.ClientID()},
		{name: "NASGetSignalStrength", msgID: qmi.NASGetSignalStrength, client: nas.ClientID()},
		{name: "NASGetSysInfo", msgID: qmi.NASGetSysInfo, client: nas.ClientID()},
		{name: "NASGetSignalInfo", msgID: 0x004F, client: nas.ClientID()},
		{name: "NASPerformNetworkScan", msgID: qmi.NASPerformNetworkScan, client: nas.ClientID()},
		{name: "NASGetCellLocationInfo", msgID: qmi.NASGetCellLocationInfo, client: nas.ClientID()},
	}

	for _, it := range items {
		resp, err := client.SendRequest(ctx, qmi.ServiceNAS, it.client, it.msgID, nil)
		if err != nil {
			fmt.Printf("%s: request error: %v\n", it.name, err)
			continue
		}
		if err := resp.CheckResult(); err != nil {
			fmt.Printf("%s: result error: %v\n", it.name, err)
			continue
		}
		fmt.Printf("%s: %d TLVs\n", it.name, len(resp.TLVs))
		for _, tlv := range resp.TLVs {
			fmt.Printf("  TLV 0x%02x len=%d val=%x\n", tlv.Type, len(tlv.Value), tlv.Value)
		}
	}
	fmt.Println()
}

func defaultQmiDevice() string {
	candidates := []string{"/dev/cdc-wdm0", "/dev/cdc-wdm1", "/dev/cdc-wdm2", "/dev/cdc-wdm3"}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/dev/cdc-wdm0"
}
