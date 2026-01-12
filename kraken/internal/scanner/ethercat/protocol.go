package ethercat

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EtherCAT constants
const (
	EtherTypeEtherCAT = 0x88A4

	// EtherCAT command types
	CmdNOP  = 0x00 // No operation
	CmdAPRD = 0x01 // Auto Increment Physical Read
	CmdAPWR = 0x02 // Auto Increment Physical Write
	CmdAPRW = 0x03 // Auto Increment Physical Read Write
	CmdFPRD = 0x04 // Configured Address Physical Read
	CmdFPWR = 0x05 // Configured Address Physical Write
	CmdFPRW = 0x06 // Configured Address Physical Read Write
	CmdBRD  = 0x07 // Broadcast Read
	CmdBWR  = 0x08 // Broadcast Write
	CmdBRW  = 0x09 // Broadcast Read Write
	CmdLRD  = 0x0A // Logical Memory Read
	CmdLWR  = 0x0B // Logical Memory Write
	CmdLRW  = 0x0C // Logical Memory Read Write
	CmdARMW = 0x0D // Auto Increment Physical Read Multiple Write
	CmdFRMW = 0x0E // Configured Address Physical Read Multiple Write

	// EtherCAT registers
	RegType           = 0x0000 // Type register (2 bytes)
	RegRevision       = 0x0001 // Revision register
	RegBuild          = 0x0002 // Build register (2 bytes)
	RegFMMU           = 0x0004 // FMMU count
	RegSyncManagers   = 0x0005 // Sync Manager count
	RegRAMSize        = 0x0006 // RAM size
	RegPortDescriptor = 0x0007 // Port descriptor
	RegESCFeatures    = 0x0008 // ESC features (2 bytes)

	RegStationAddr  = 0x0010 // Configured station address (2 bytes)
	RegStationAlias = 0x0012 // Configured station alias (2 bytes)

	RegDLControl = 0x0100 // DL Control register (4 bytes)
	RegDLPort    = 0x0101 // DL Port register
	RegDLAlias   = 0x0103 // DL Alias register
	RegDLStatus  = 0x0110 // DL Status register (2 bytes)

	RegALControl = 0x0120 // AL Control register (2 bytes)
	RegALStatus  = 0x0130 // AL Status register (2 bytes)
	RegALCode    = 0x0134 // AL Status Code (2 bytes)

	// EEPROM registers
	RegEEPROMConfig  = 0x0500 // EEPROM configuration
	RegEEPROMPDICtrl = 0x0501 // EEPROM PDI access state
	RegEEPROMControl = 0x0502 // EEPROM control/status (2 bytes)
	RegEEPROMAddress = 0x0504 // EEPROM address (4 bytes)
	RegEEPROMData    = 0x0508 // EEPROM data (8 bytes)

	// EEPROM offsets (word addresses)
	EEPROMVendorID    = 0x0008 // Vendor ID (4 bytes)
	EEPROMProductCode = 0x000A // Product Code (4 bytes)
	EEPROMRevisionNo  = 0x000C // Revision Number (4 bytes)
	EEPROMSerialNo    = 0x000E // Serial Number (4 bytes)

	// Frame constants
	MaxDataLen   = 1486 // Max EtherCAT datagram data length
	HeaderLen    = 2    // EtherCAT header length
	DatagramHdr  = 10   // Datagram header length (without data)
	BroadcastMAC = "\xff\xff\xff\xff\xff\xff"
)

// Datagram represents an EtherCAT datagram within a frame.
type Datagram struct {
	Cmd     uint8  // Command type
	Index   uint8  // Datagram index for correlation
	Address uint32 // Address (interpretation depends on cmd)
	Data    []byte // Data payload
	WKC     uint16 // Working counter (set by slaves)
}

// SetAutoIncAddr sets address for auto-increment commands (position + offset).
func (d *Datagram) SetAutoIncAddr(position int16, offset uint16) {
	d.Address = uint32(uint16(position)) | (uint32(offset) << 16)
}

// SetConfiguredAddr sets address for configured address commands.
func (d *Datagram) SetConfiguredAddr(stationAddr, offset uint16) {
	d.Address = uint32(stationAddr) | (uint32(offset) << 16)
}

// Frame represents a complete EtherCAT frame (without Ethernet header).
type Frame struct {
	Datagrams []Datagram
}

// Build serializes the EtherCAT frame to bytes.
func (f *Frame) Build() ([]byte, error) {
	if len(f.Datagrams) == 0 {
		return nil, errors.New("ethercat: frame has no datagrams")
	}

	// Calculate total length
	totalLen := HeaderLen
	for _, dg := range f.Datagrams {
		totalLen += DatagramHdr + len(dg.Data) + 2 // +2 for WKC
	}

	if totalLen > MaxDataLen+HeaderLen {
		return nil, fmt.Errorf("ethercat: frame too large (%d bytes)", totalLen)
	}

	buf := make([]byte, totalLen)

	// EtherCAT header: length (11 bits) + reserved (1 bit) + type (4 bits)
	// Type 1 = EtherCAT commands
	frameLen := totalLen - HeaderLen
	header := uint16(frameLen&0x7FF) | (1 << 12)
	binary.LittleEndian.PutUint16(buf[0:2], header)

	offset := HeaderLen
	for i, dg := range f.Datagrams {
		// Datagram header
		buf[offset] = dg.Cmd
		buf[offset+1] = dg.Index

		binary.LittleEndian.PutUint32(buf[offset+2:offset+6], dg.Address)

		// Length + flags (M bit for more datagrams, C bit for circulating)
		dataLen := uint16(len(dg.Data))
		lenFlags := dataLen & 0x7FF
		if i < len(f.Datagrams)-1 {
			lenFlags |= 0x8000 // M bit: more datagrams follow
		}
		binary.LittleEndian.PutUint16(buf[offset+6:offset+8], lenFlags)

		// IRQ (not used, set to 0)
		binary.LittleEndian.PutUint16(buf[offset+8:offset+10], 0)

		offset += DatagramHdr

		// Data
		copy(buf[offset:], dg.Data)
		offset += len(dg.Data)

		// WKC (working counter, slaves will increment)
		binary.LittleEndian.PutUint16(buf[offset:offset+2], dg.WKC)
		offset += 2
	}

	return buf, nil
}

// ParseFrame parses an EtherCAT frame from bytes.
func ParseFrame(data []byte) (*Frame, error) {
	if len(data) < HeaderLen {
		return nil, errors.New("ethercat: frame too short")
	}

	header := binary.LittleEndian.Uint16(data[0:2])
	frameLen := int(header & 0x7FF)
	frameType := (header >> 12) & 0x0F

	if frameType != 1 {
		return nil, fmt.Errorf("ethercat: unexpected frame type %d", frameType)
	}

	if len(data) < HeaderLen+frameLen {
		return nil, fmt.Errorf("ethercat: frame truncated (expected %d, got %d)", HeaderLen+frameLen, len(data))
	}

	frame := &Frame{}
	offset := HeaderLen

	for offset < HeaderLen+frameLen {
		if offset+DatagramHdr > len(data) {
			return nil, errors.New("ethercat: datagram header truncated")
		}

		dg := Datagram{
			Cmd:     data[offset],
			Index:   data[offset+1],
			Address: binary.LittleEndian.Uint32(data[offset+2 : offset+6]),
		}

		lenFlags := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		dataLen := int(lenFlags & 0x7FF)
		more := (lenFlags & 0x8000) != 0

		offset += DatagramHdr

		if offset+dataLen+2 > len(data) {
			return nil, errors.New("ethercat: datagram data truncated")
		}

		dg.Data = make([]byte, dataLen)
		copy(dg.Data, data[offset:offset+dataLen])
		offset += dataLen

		dg.WKC = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2

		frame.Datagrams = append(frame.Datagrams, dg)

		if !more {
			break
		}
	}

	return frame, nil
}

// BuildBRD creates a Broadcast Read datagram.
func BuildBRD(index uint8, offset uint16, length int) Datagram {
	dg := Datagram{
		Cmd:   CmdBRD,
		Index: index,
		Data:  make([]byte, length),
	}
	dg.SetAutoIncAddr(0, offset)
	return dg
}

// BuildAPRD creates an Auto Increment Physical Read datagram.
func BuildAPRD(index uint8, position int16, offset uint16, length int) Datagram {
	dg := Datagram{
		Cmd:   CmdAPRD,
		Index: index,
		Data:  make([]byte, length),
	}
	dg.SetAutoIncAddr(position, offset)
	return dg
}

// BuildAPWR creates an Auto Increment Physical Write datagram.
func BuildAPWR(index uint8, position int16, offset uint16, data []byte) Datagram {
	dg := Datagram{
		Cmd:   CmdAPWR,
		Index: index,
		Data:  data,
	}
	dg.SetAutoIncAddr(position, offset)
	return dg
}

// BuildFPRD creates a Configured Address Physical Read datagram.
func BuildFPRD(index uint8, stationAddr, offset uint16, length int) Datagram {
	dg := Datagram{
		Cmd:   CmdFPRD,
		Index: index,
		Data:  make([]byte, length),
	}
	dg.SetConfiguredAddr(stationAddr, offset)
	return dg
}

// BuildFPWR creates a Configured Address Physical Write datagram.
func BuildFPWR(index uint8, stationAddr, offset uint16, data []byte) Datagram {
	dg := Datagram{
		Cmd:   CmdFPWR,
		Index: index,
		Data:  data,
	}
	dg.SetConfiguredAddr(stationAddr, offset)
	return dg
}
