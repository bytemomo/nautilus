package packet

import (
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CraftPacket creates a full TCP packet with the given payload.
func CraftPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1105024978,
		Ack:     1,
		Window:  14600,
		ACK:     true,
		PSH:     true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buffer, opts, tcpLayer, gopacket.Payload(payload)); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// Send sends a raw packet to the specified destination IP.
func Send(dstIP net.IP, packet []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrInet4{
		Port: 0,
	}
	copy(addr.Addr[:], dstIP.To4())

	return syscall.Sendto(fd, packet, 0, &addr)
}
