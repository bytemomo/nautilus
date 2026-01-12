package ethercat

import (
	"bytes"
	"testing"
)

func TestDatagramSetAutoIncAddr(t *testing.T) {
	dg := Datagram{}
	dg.SetAutoIncAddr(-5, 0x0110)

	// Position -5 as uint16 = 0xFFFB, offset 0x0110
	// Address = position | (offset << 16) = 0xFFFB | 0x01100000 = 0x0110FFFB
	expected := uint32(0x0110FFFB)
	if dg.Address != expected {
		t.Errorf("expected address 0x%08X, got 0x%08X", expected, dg.Address)
	}
}

func TestDatagramSetConfiguredAddr(t *testing.T) {
	dg := Datagram{}
	dg.SetConfiguredAddr(0x1001, 0x0130)

	// Address = stationAddr | (offset << 16) = 0x1001 | 0x01300000 = 0x01301001
	expected := uint32(0x01301001)
	if dg.Address != expected {
		t.Errorf("expected address 0x%08X, got 0x%08X", expected, dg.Address)
	}
}

func TestBuildBRD(t *testing.T) {
	dg := BuildBRD(0x01, RegType, 2)

	if dg.Cmd != CmdBRD {
		t.Errorf("expected cmd %d, got %d", CmdBRD, dg.Cmd)
	}
	if dg.Index != 0x01 {
		t.Errorf("expected index 1, got %d", dg.Index)
	}
	if len(dg.Data) != 2 {
		t.Errorf("expected data len 2, got %d", len(dg.Data))
	}
}

func TestBuildAPWR(t *testing.T) {
	data := []byte{0x01, 0x10}
	dg := BuildAPWR(0x02, -3, RegStationAddr, data)

	if dg.Cmd != CmdAPWR {
		t.Errorf("expected cmd %d, got %d", CmdAPWR, dg.Cmd)
	}
	if dg.Index != 0x02 {
		t.Errorf("expected index 2, got %d", dg.Index)
	}
	if !bytes.Equal(dg.Data, data) {
		t.Errorf("data mismatch")
	}
}

func TestFrameBuildAndParse(t *testing.T) {
	original := &Frame{
		Datagrams: []Datagram{
			{Cmd: CmdBRD, Index: 1, Address: 0x00000000, Data: make([]byte, 2)},
			{Cmd: CmdAPRD, Index: 2, Address: 0x01100005, Data: make([]byte, 4)},
		},
	}

	built, err := original.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	parsed, err := ParseFrame(built)
	if err != nil {
		t.Fatalf("ParseFrame failed: %v", err)
	}

	if len(parsed.Datagrams) != len(original.Datagrams) {
		t.Fatalf("expected %d datagrams, got %d", len(original.Datagrams), len(parsed.Datagrams))
	}

	for i, origDg := range original.Datagrams {
		parsedDg := parsed.Datagrams[i]
		if parsedDg.Cmd != origDg.Cmd {
			t.Errorf("dg[%d] cmd: expected %d, got %d", i, origDg.Cmd, parsedDg.Cmd)
		}
		if parsedDg.Index != origDg.Index {
			t.Errorf("dg[%d] index: expected %d, got %d", i, origDg.Index, parsedDg.Index)
		}
		if parsedDg.Address != origDg.Address {
			t.Errorf("dg[%d] address: expected 0x%08X, got 0x%08X", i, origDg.Address, parsedDg.Address)
		}
		if len(parsedDg.Data) != len(origDg.Data) {
			t.Errorf("dg[%d] data len: expected %d, got %d", i, len(origDg.Data), len(parsedDg.Data))
		}
	}
}

func TestFrameBuildEmpty(t *testing.T) {
	frame := &Frame{}
	_, err := frame.Build()
	if err == nil {
		t.Error("expected error for empty frame")
	}
}

func TestParseFrameTruncated(t *testing.T) {
	// Too short for header
	_, err := ParseFrame([]byte{0x00})
	if err == nil {
		t.Error("expected error for truncated frame")
	}
}

func TestParseFrameWrongType(t *testing.T) {
	// Frame with type 0 instead of 1
	data := []byte{0x10, 0x00} // length 16, type 0
	_, err := ParseFrame(data)
	if err == nil {
		t.Error("expected error for wrong frame type")
	}
}
