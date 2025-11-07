package packet

import (
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// Packet provides methods for crafting and sending packets.
type Packet struct {
	logger *logrus.Logger
}

// New creates a new Packet instance.
func New(logger *logrus.Logger) *Packet {
	return &Packet{logger: logger}
}

// CraftPacket creates a full TCP packet with the given payload.
func (p *Packet) CraftPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
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
		p.logger.Errorf("Failed to serialize packet layers: %v", err)
		return nil, err
	}

	p.logger.Infof("Crafted TCP packet from %s:%d to %s:%d with payload size %d", srcIP, srcPort, dstIP, dstPort, len(payload))
	return buffer.Bytes(), nil
}

// Send sends a raw packet to the specified destination IP.
func (p *Packet) Send(dstIP net.IP, packet []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		p.logger.Errorf("Failed to create raw socket: %v", err)
		return err
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrInet4{
		Port: 0,
	}
	copy(addr.Addr[:], dstIP.To4())

	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		p.logger.Errorf("Failed to send packet: %v", err)
		return err
	}

	p.logger.Infof("Sent raw packet to %s", dstIP)
	return nil
}
