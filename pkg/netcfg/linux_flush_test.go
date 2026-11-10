//go:build linux

package netcfg

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

type stubLink struct {
	attrs netlink.LinkAttrs
}

func (l *stubLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *stubLink) Type() string              { return "stub" }

func TestFlushAddressesReturnsLinkLookupError(t *testing.T) {
	restore := stubNetlinkOps()
	defer restore()

	netlinkLinkByName = func(string) (netlink.Link, error) {
		return nil, errors.New("no such link")
	}

	err := (&LinuxConfigurator{}).FlushAddresses("qmimux0")
	if err == nil || !strings.Contains(err.Error(), "lookup interface qmimux0") {
		t.Fatalf("FlushAddresses() error = %v, want lookup context", err)
	}
}

func TestFlushAddressesReturnsAddrListError(t *testing.T) {
	restore := stubNetlinkOps()
	defer restore()

	link := &stubLink{}
	netlinkLinkByName = func(string) (netlink.Link, error) { return link, nil }
	netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return nil, errors.New("addr list failed")
	}

	err := (&LinuxConfigurator{}).FlushAddresses("qmimux0")
	if err == nil || !strings.Contains(err.Error(), "list addresses on qmimux0") {
		t.Fatalf("FlushAddresses() error = %v, want addr list context", err)
	}
}

func TestFlushAddressesJoinsAddrDeleteErrors(t *testing.T) {
	restore := stubNetlinkOps()
	defer restore()

	link := &stubLink{}
	netlinkLinkByName = func(string) (netlink.Link, error) { return link, nil }
	netlinkAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{
			{IPNet: &net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(32, 32)}},
			{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(128, 128)}},
		}, nil
	}
	calls := 0
	netlinkAddrDel = func(netlink.Link, *netlink.Addr) error {
		calls++
		if calls == 1 {
			return errors.New("addrdel-1")
		}
		return errors.New("addrdel-2")
	}

	err := (&LinuxConfigurator{}).FlushAddresses("qmimux0")
	if err == nil {
		t.Fatal("FlushAddresses() error = nil, want joined delete errors")
	}
	for _, want := range []string{"delete address from qmimux0", "addrdel-1", "addrdel-2"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("FlushAddresses() error = %v, want substring %q", err, want)
		}
	}
}

func TestFlushRoutesJoinsRouteDeleteErrors(t *testing.T) {
	restore := stubNetlinkOps()
	defer restore()

	link := &stubLink{}
	netlinkLinkByName = func(string) (netlink.Link, error) { return link, nil }
	netlinkRouteList = func(netlink.Link, int) ([]netlink.Route, error) {
		return []netlink.Route{
			{LinkIndex: 1},
			{LinkIndex: 1, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}},
		}, nil
	}
	calls := 0
	netlinkRouteDel = func(*netlink.Route) error {
		calls++
		if calls == 1 {
			return errors.New("routedel-1")
		}
		return errors.New("routedel-2")
	}

	err := (&LinuxConfigurator{}).FlushRoutes("qmimux0")
	if err == nil {
		t.Fatal("FlushRoutes() error = nil, want joined delete errors")
	}
	for _, want := range []string{"delete route from qmimux0", "routedel-1", "routedel-2"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("FlushRoutes() error = %v, want substring %q", err, want)
		}
	}
}

func TestAddDefaultRouteUsesRouteAppendAcrossMultipleInterfaces(t *testing.T) {
	restore := stubNetlinkOps()
	defer restore()

	links := map[string]*stubLink{
		"qmimux0": {attrs: netlink.LinkAttrs{Index: 10, Name: "qmimux0"}},
		"qmimux1": {attrs: netlink.LinkAttrs{Index: 11, Name: "qmimux1"}},
	}
	routesByLink := map[int][]netlink.Route{}

	netlinkLinkByName = func(name string) (netlink.Link, error) {
		if link, ok := links[name]; ok {
			return link, nil
		}
		return nil, errors.New("no such link")
	}
	netlinkRouteList = func(link netlink.Link, _ int) ([]netlink.Route, error) {
		return append([]netlink.Route(nil), routesByLink[link.Attrs().Index]...), nil
	}
	var appended []netlink.Route
	netlinkRouteAppend = func(route *netlink.Route) error {
		appended = append(appended, *route)
		routesByLink[route.LinkIndex] = append(routesByLink[route.LinkIndex], *route)
		return nil
	}
	var deleted []netlink.Route
	netlinkRouteDel = func(route *netlink.Route) error {
		deleted = append(deleted, *route)
		existing := routesByLink[route.LinkIndex]
		filtered := existing[:0]
		for _, item := range existing {
			if !sameDefaultRoute(item, *route) {
				filtered = append(filtered, item)
			}
		}
		routesByLink[route.LinkIndex] = filtered
		return nil
	}

	cfg := &LinuxConfigurator{}
	gw0 := net.ParseIP("10.0.0.1")
	gw1 := net.ParseIP("10.0.1.1")
	if err := cfg.AddDefaultRoute("qmimux0", gw0); err != nil {
		t.Fatalf("AddDefaultRoute(qmimux0) error = %v", err)
	}
	if err := cfg.AddDefaultRoute("qmimux1", gw1); err != nil {
		t.Fatalf("AddDefaultRoute(qmimux1) error = %v", err)
	}
	if len(appended) != 2 {
		t.Fatalf("RouteAppend calls = %d, want 2", len(appended))
	}
	if appended[0].LinkIndex != 10 || appended[1].LinkIndex != 11 {
		t.Fatalf("appended link indices = [%d, %d], want [10, 11]", appended[0].LinkIndex, appended[1].LinkIndex)
	}
	if appended[0].Priority != 5000 || appended[1].Priority != 5000 {
		t.Fatalf("appended priorities = [%d, %d], want [5000, 5000]", appended[0].Priority, appended[1].Priority)
	}

	// Repeating the identical route on qmimux0 is idempotent.
	if err := cfg.AddDefaultRoute("qmimux0", gw0); err != nil {
		t.Fatalf("idempotent AddDefaultRoute(qmimux0) error = %v", err)
	}
	if len(appended) != 2 || len(deleted) != 0 {
		t.Fatalf("after idempotent call: appended=%d deleted=%d, want 2 and 0", len(appended), len(deleted))
	}

	// Changing gateway on qmimux0 replaces qmimux0's stale default route while preserving qmimux1.
	gw0New := net.ParseIP("10.0.0.2")
	if err := cfg.AddDefaultRoute("qmimux0", gw0New); err != nil {
		t.Fatalf("AddDefaultRoute(qmimux0, new gw) error = %v", err)
	}
	if len(deleted) != 1 || !deleted[0].Gw.Equal(gw0) {
		t.Fatalf("deleted routes = %+v, want stale gateway %v", deleted, gw0)
	}
	if len(routesByLink[11]) != 1 || !routesByLink[11][0].Gw.Equal(gw1) {
		t.Fatalf("qmimux1 routes = %+v, want preserved route via %v", routesByLink[11], gw1)
	}
}

func TestAddDefaultRouteDirectUsesRouteAppendAcrossMultipleInterfaces(t *testing.T) {
	restore := stubNetlinkOps()
	defer restore()

	links := map[string]*stubLink{
		"qmimux0": {attrs: netlink.LinkAttrs{Index: 10, Name: "qmimux0"}},
		"qmimux1": {attrs: netlink.LinkAttrs{Index: 11, Name: "qmimux1"}},
	}
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		if link, ok := links[name]; ok {
			return link, nil
		}
		return nil, errors.New("no such link")
	}
	netlinkRouteList = func(netlink.Link, int) ([]netlink.Route, error) {
		return nil, nil
	}
	var appended []netlink.Route
	netlinkRouteAppend = func(route *netlink.Route) error {
		appended = append(appended, *route)
		return nil
	}

	cfg := &LinuxConfigurator{}
	if err := cfg.AddDefaultRouteDirect("qmimux0", false); err != nil {
		t.Fatalf("AddDefaultRouteDirect(qmimux0) error = %v", err)
	}
	if err := cfg.AddDefaultRouteDirect("qmimux1", false); err != nil {
		t.Fatalf("AddDefaultRouteDirect(qmimux1) error = %v", err)
	}
	if len(appended) != 2 {
		t.Fatalf("RouteAppend calls = %d, want 2", len(appended))
	}
	if appended[0].LinkIndex != 10 || appended[1].LinkIndex != 11 {
		t.Fatalf("appended link indices = [%d, %d], want [10, 11]", appended[0].LinkIndex, appended[1].LinkIndex)
	}
	if appended[0].Priority != 512 || appended[1].Priority != 512 {
		t.Fatalf("appended priorities = [%d, %d], want [512, 512]", appended[0].Priority, appended[1].Priority)
	}
}

func stubNetlinkOps() func() {
	oldLinkByName := netlinkLinkByName
	oldAddrList := netlinkAddrList
	oldAddrDel := netlinkAddrDel
	oldRouteList := netlinkRouteList
	oldRouteAppend := netlinkRouteAppend
	oldRouteDel := netlinkRouteDel
	return func() {
		netlinkLinkByName = oldLinkByName
		netlinkAddrList = oldAddrList
		netlinkAddrDel = oldAddrDel
		netlinkRouteList = oldRouteList
		netlinkRouteAppend = oldRouteAppend
		netlinkRouteDel = oldRouteDel
	}
}
