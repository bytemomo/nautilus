package ethercat

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/protocol"
	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/datalink"

	"github.com/sirupsen/logrus"
)


// Scanner discovers EtherCAT slaves on a network interface.
type Scanner struct {
	Log       *logrus.Entry
	Config    domain.EtherCATScannerConfig
	conduit   conduit.Conduit[conduit.Frame]
	frame     conduit.Frame
	dgIndex   uint8
	baseAddr  uint16
}

// New creates a new EtherCAT scanner for the given interface.
func New(log *logrus.Entry, cfg domain.EtherCATScannerConfig) *Scanner {
	return &Scanner{
		Log:      log,
		Config:   cfg,
		baseAddr: 0x1000, // Starting station address for enumeration
	}
}

// Type returns the scanner type identifier.
func (s *Scanner) Type() string { return "ethercat" }

func (s *Scanner) nextIndex() uint8 {
	idx := s.dgIndex
	s.dgIndex++
	return idx
}

// Execute scans for EtherCAT slaves and returns classified targets.
func (s *Scanner) Execute(ctx context.Context) ([]domain.ClassifiedTarget, error) {
	if s.Config.Interface == "" {
		return nil, fmt.Errorf("ethercat: interface not specified")
	}

	log := s.Log.WithField("iface", s.Config.Interface)
	log.Info("Starting EtherCAT scan")

	// Create Ethernet conduit for EtherCAT
	broadcast := net.HardwareAddr([]byte(BroadcastMAC))
	s.conduit = datalink.Ethernet(s.Config.Interface, broadcast, EtherTypeEtherCAT)

	timeout := s.Config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := s.conduit.Dial(scanCtx); err != nil {
		return nil, fmt.Errorf("ethercat: dial failed: %w", err)
	}
	defer s.conduit.Close()

	s.frame = s.conduit.Underlying()

	// Step 1: Count slaves using broadcast read to TYPE register
	slaveCount, err := s.countSlaves(scanCtx)
	if err != nil {
		return nil, fmt.Errorf("ethercat: count slaves: %w", err)
	}

	log.WithField("slave_count", slaveCount).Info("Discovered slaves")

	if slaveCount == 0 {
		return nil, nil
	}

	// Step 2: Enumerate and configure each slave
	var targets []domain.ClassifiedTarget
	for i := 0; i < slaveCount; i++ {
		slave, err := s.enumerateSlave(scanCtx, i)
		if err != nil {
			log.WithError(err).WithField("position", i).Warn("Failed to enumerate slave")
			continue
		}

		log.WithFields(logrus.Fields{
			"position":     slave.Position,
			"station_addr": slave.StationAddr,
			"vendor_id":    fmt.Sprintf("0x%08X", slave.VendorID),
			"product_code": fmt.Sprintf("0x%08X", slave.ProductCode),
		}).Debug("Enumerated slave")

		target := domain.ClassifiedTarget{
			Target: slave,
			Tags:   s.deriveTags(slave),
		}
		targets = append(targets, target)
	}

	log.WithField("target_count", len(targets)).Info("EtherCAT scan complete")
	return targets, nil
}

// countSlaves sends a broadcast read to TYPE register; WKC indicates slave count.
func (s *Scanner) countSlaves(ctx context.Context) (int, error) {
	dg := BuildBRD(s.nextIndex(), RegType, 2)
	frame := &Frame{Datagrams: []Datagram{dg}}

	resp, err := s.sendFrame(ctx, frame)
	if err != nil {
		return 0, err
	}

	if len(resp.Datagrams) == 0 {
		return 0, nil
	}

	return int(resp.Datagrams[0].WKC), nil
}

// enumerateSlave configures and reads info for a slave at the given position.
func (s *Scanner) enumerateSlave(ctx context.Context, position int) (domain.EtherCATSlave, error) {
	slave := domain.EtherCATSlave{
		Interface: s.Config.Interface,
		Position:  uint16(position),
	}

	// Assign station address using APWR
	stationAddr := s.baseAddr + uint16(position)
	addrData := make([]byte, 2)
	binary.LittleEndian.PutUint16(addrData, stationAddr)

	dg := BuildAPWR(s.nextIndex(), -int16(position), RegStationAddr, addrData)
	frame := &Frame{Datagrams: []Datagram{dg}}

	resp, err := s.sendFrame(ctx, frame)
	if err != nil {
		return slave, fmt.Errorf("assign station addr: %w", err)
	}

	if len(resp.Datagrams) == 0 || resp.Datagrams[0].WKC != 1 {
		return slave, fmt.Errorf("station addr write failed (WKC=%d)", resp.Datagrams[0].WKC)
	}

	slave.StationAddr = stationAddr

	// Read DL Status
	dlStatus, err := s.readRegister(ctx, stationAddr, RegDLStatus, 2)
	if err != nil {
		s.Log.WithError(err).Debug("Failed to read DL status")
	} else if len(dlStatus) >= 2 {
		slave.PortStatus = binary.LittleEndian.Uint16(dlStatus)
	}

	// Read EEPROM data (Vendor ID, Product Code, etc.)
	vendorID, err := s.readEEPROM(ctx, stationAddr, EEPROMVendorID)
	if err != nil {
		s.Log.WithError(err).Debug("Failed to read vendor ID")
	} else {
		slave.VendorID = vendorID
	}

	productCode, err := s.readEEPROM(ctx, stationAddr, EEPROMProductCode)
	if err != nil {
		s.Log.WithError(err).Debug("Failed to read product code")
	} else {
		slave.ProductCode = productCode
	}

	revisionNo, err := s.readEEPROM(ctx, stationAddr, EEPROMRevisionNo)
	if err != nil {
		s.Log.WithError(err).Debug("Failed to read revision")
	} else {
		slave.RevisionNo = revisionNo
	}

	serialNo, err := s.readEEPROM(ctx, stationAddr, EEPROMSerialNo)
	if err != nil {
		s.Log.WithError(err).Debug("Failed to read serial")
	} else {
		slave.SerialNo = serialNo
	}

	return slave, nil
}

// readRegister reads a register from a configured slave.
func (s *Scanner) readRegister(ctx context.Context, stationAddr, offset uint16, length int) ([]byte, error) {
	dg := BuildFPRD(s.nextIndex(), stationAddr, offset, length)
	frame := &Frame{Datagrams: []Datagram{dg}}

	resp, err := s.sendFrame(ctx, frame)
	if err != nil {
		return nil, err
	}

	if len(resp.Datagrams) == 0 || resp.Datagrams[0].WKC != 1 {
		return nil, fmt.Errorf("read failed (WKC=%d)", resp.Datagrams[0].WKC)
	}

	return resp.Datagrams[0].Data, nil
}

// readEEPROM reads a 32-bit value from EEPROM.
func (s *Scanner) readEEPROM(ctx context.Context, stationAddr uint16, wordAddr uint16) (uint32, error) {
	// Write EEPROM address
	addrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(addrData, uint32(wordAddr))

	dg := BuildFPWR(s.nextIndex(), stationAddr, RegEEPROMAddress, addrData)
	frame := &Frame{Datagrams: []Datagram{dg}}
	if _, err := s.sendFrame(ctx, frame); err != nil {
		return 0, fmt.Errorf("write eeprom addr: %w", err)
	}

	// Issue read command (0x0100 = read, 2 words)
	ctrlData := make([]byte, 2)
	binary.LittleEndian.PutUint16(ctrlData, 0x0100)

	dg = BuildFPWR(s.nextIndex(), stationAddr, RegEEPROMControl, ctrlData)
	frame = &Frame{Datagrams: []Datagram{dg}}
	if _, err := s.sendFrame(ctx, frame); err != nil {
		return 0, fmt.Errorf("write eeprom ctrl: %w", err)
	}

	// Poll for completion
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Millisecond)

		data, err := s.readRegister(ctx, stationAddr, RegEEPROMControl, 2)
		if err != nil {
			continue
		}
		status := binary.LittleEndian.Uint16(data)
		if (status & 0x8000) == 0 { // Not busy
			break
		}
	}

	// Read data (4 bytes from EEPROM data register)
	data, err := s.readRegister(ctx, stationAddr, RegEEPROMData, 4)
	if err != nil {
		return 0, fmt.Errorf("read eeprom data: %w", err)
	}

	if len(data) < 4 {
		return 0, fmt.Errorf("eeprom data too short")
	}

	return binary.LittleEndian.Uint32(data), nil
}

// sendFrame sends an EtherCAT frame and waits for response.
func (s *Scanner) sendFrame(ctx context.Context, f *Frame) (*Frame, error) {
	payload, err := f.Build()
	if err != nil {
		return nil, err
	}

	buf := conduit.GetBuf(len(payload))
	copy(buf.Bytes(), payload)

	pkt := &conduit.FramePkt{
		Data:      buf,
		EtherType: EtherTypeEtherCAT,
	}

	if _, _, err := s.frame.Send(ctx, pkt, nil); err != nil {
		buf.Release()
		return nil, fmt.Errorf("send: %w", err)
	}

	// Receive response
	resp, err := s.frame.Recv(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}
	defer resp.Data.Release()

	if resp.EtherType != EtherTypeEtherCAT {
		return nil, fmt.Errorf("unexpected ethertype: 0x%04X", resp.EtherType)
	}

	return ParseFrame(resp.Data.Bytes())
}

// deriveTags generates tags for an EtherCAT slave using the protocol package.
func (s *Scanner) deriveTags(slave domain.EtherCATSlave) []domain.Tag {
	return protocol.DeriveTagsFromEtherCAT(slave)
}
