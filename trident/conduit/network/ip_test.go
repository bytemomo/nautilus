package network_test

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	cond "bytemomo/trident/conduit"
	net "bytemomo/trident/conduit/network"
)

func TestMain(m *testing.M) {
	// Check if we are running as root
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Failed to check user ID:", err)
		return
	}
	if string(output) != "0\n" {
		fmt.Println("Network tests must be run as root")
		return
	}

	// Create veth pair
	cmd = exec.Command("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
	if err := cmd.Run(); err != nil {
		fmt.Println("Failed to create veth pair:", err)
		return
	}
	defer exec.Command("ip", "link", "del", "veth0").Run()

	// Bring up veth interfaces
	cmd = exec.Command("ip", "link", "set", "veth0", "up")
	if err := cmd.Run(); err != nil {
		fmt.Println("Failed to bring up veth0:", err)
		return
	}
	cmd = exec.Command("ip", "link", "set", "veth1", "up")
	if err := cmd.Run(); err != nil {
		fmt.Println("Failed to bring up veth1:", err)
		return
	}

	// Assign IP addresses
	cmd = exec.Command("ip", "addr", "add", "192.168.1.1/24", "dev", "veth0")
	if err := cmd.Run(); err != nil {
		fmt.Println("Failed to assign IP to veth0:", err)
		return
	}
	cmd = exec.Command("ip", "addr", "add", "192.168.1.2/24", "dev", "veth1")
	if err := cmd.Run(); err != nil {
		fmt.Println("Failed to assign IP to veth1:", err)
		return
	}

	m.Run()
}

func TestIpConduit_SendRecv(t *testing.T) {
	// Create conduits
	raddr, _ := netip.ParseAddr("192.168.1.2")
	conduit0 := net.IPRaw(253, raddr)
	conduit1 := net.IPRaw(253, netip.Addr{})

	// Dial conduits
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conduit0.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	defer conduit0.Close()
	if err := conduit1.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	defer conduit1.Close()

	// Send a packet
	payload := []byte("hello world")
	buf := cond.GetBuf(len(payload))
	copy(buf.Bytes(), payload)
	pkt := &cond.IPPacket{
		Data: buf,
		Dst:  raddr,
	}
	go func() {
		_, _, err := conduit0.Underlying().Send(ctx, pkt, nil)
		if err != nil {
			t.Error(err)
		}
	}()

	// Receive the packet
	recvPkt, err := conduit1.Underlying().Recv(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check the payload
	if string(recvPkt.Data.Bytes()) != string(payload) {
		t.Errorf("unexpected payload: got %q, want %q", string(recvPkt.Data.Bytes()), string(payload))
	}
}
