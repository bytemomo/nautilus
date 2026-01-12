package datalink_test

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"bytemomo/trident/conduit"
	dl "bytemomo/trident/conduit/datalink"
	"bytemomo/trident/conduit/utils"
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
		fmt.Println("Datalink tests must be run as root")
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

	m.Run()
}

func TestEthernetConduit_SendRecv(t *testing.T) {
	// Get interfaces
	veth0, err := net.InterfaceByName("veth0")
	if err != nil {
		t.Fatal(err)
	}
	veth1, err := net.InterfaceByName("veth1")
	if err != nil {
		t.Fatal(err)
	}

	// Create conduits
	conduit0 := dl.Ethernet("veth0", veth1.HardwareAddr, dl.EtherTypeEtherCAT)
	conduit1 := dl.Ethernet("veth1", veth0.HardwareAddr, dl.EtherTypeEtherCAT)

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

	// Send a frame
	payload := []byte("hello world")
	buf := utils.GetBuf(len(payload))
	copy(buf.Bytes(), payload)
	pkt := &conduit.FramePkt{
		Data:      buf,
		Dst:       veth1.HardwareAddr,
		EtherType: 0x88a4,
	}
	go func() {
		_, _, err := conduit0.Underlying().Send(ctx, pkt, nil)
		if err != nil {
			t.Error(err)
		}
	}()

	// Receive the frame
	recvPkt, err := conduit1.Underlying().Recv(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check the payload
	if string(recvPkt.Data.Bytes()) != string(payload) {
		t.Errorf("unexpected payload: got %q, want %q", string(recvPkt.Data.Bytes()), string(payload))
	}
}
