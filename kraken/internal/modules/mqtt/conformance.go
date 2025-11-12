package mqtt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/native"
	cnd "bytemomo/trident/conduit"
)

const (
	mqttKeepAliveSeconds = 30
	testTimeout          = 5 * time.Second
)

func Init() {
	native.Register("mqtt-conformance-test", native.Descriptor{
		Run:  runConformanceTests,
		Kind: cnd.KindStream,
		Stack: []domain.LayerHint{
			{Name: "tcp"},
		},
	})
}

func runConformanceTests(ctx context.Context, mod *domain.Module, target domain.HostPort, res native.Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}
	if res.StreamFactory == nil {
		return result, errors.New("mqtt-conformance-test requires a conduit stream")
	}

	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	handle, cleanup, err := res.StreamFactory(runCtx)
	if err != nil {
		return result, fmt.Errorf("dial conduit: %w", err)
	}
	defer cleanup()

	stream, ok := handle.(cnd.Stream)
	if !ok {
		return result, fmt.Errorf("unexpected conduit type %T", handle)
	}

	client := &mqttClient{
		ctx:    runCtx,
		stream: stream,
		pid:    1,
	}

	var logs []string
	var findings []domain.Finding
	topic := fmt.Sprintf("kraken/conformance/%d", time.Now().UnixNano())
	payload := []byte("kraken-mqtt-conformance")
	clientID := fmt.Sprintf("kraken-%d", time.Now().UnixNano())

	tests := []struct {
		name string
		fn   func() error
	}{
		{"connect", func() error {
			if err := client.connect(clientID); err != nil {
				return err
			}
			return client.expectConnAck()
		}},
		{"subscribe-loopback", func() error {
			if err := client.subscribe(topic, 0); err != nil {
				return err
			}
			return client.expectSubAck()
		}},
		{"publish-loopback", func() error {
			if err := client.publish(topic, payload); err != nil {
				return err
			}
			return client.expectPublish(topic, payload)
		}},
	}

	for _, test := range tests {
		err := test.fn()
		logLine := fmt.Sprintf("[%s] %s", test.name, statusMessage(err))
		logs = append(logs, logLine)
		findings = append(findings, buildFinding(mod.ModuleID, target, test.name, err))
		if err != nil {
			break
		}
	}

	result.Findings = findings
	result.Logs = logs
	return result, nil
}

func statusMessage(err error) string {
	if err != nil {
		return fmt.Sprintf("FAIL: %v", err)
	}
	return "PASS"
}

func buildFinding(moduleID string, target domain.HostPort, testName string, err error) domain.Finding {
	success := err == nil
	severity := "info"
	description := "Test completed successfully"
	if !success {
		severity = "medium"
		description = err.Error()
	}
	return domain.Finding{
		ID:          fmt.Sprintf("%s-%s", moduleID, strings.ReplaceAll(testName, " ", "-")),
		ModuleID:    moduleID,
		Success:     success,
		Title:       fmt.Sprintf("MQTT %s", testName),
		Severity:    severity,
		Description: description,
		Tags:        []domain.Tag{"protocol:mqtt"},
		Timestamp:   time.Now().UTC(),
		Target:      target,
	}
}

type mqttClient struct {
	ctx    context.Context
	stream cnd.Stream
	pid    uint16
}

func (c *mqttClient) connect(clientID string) error {
	vh := bytes.NewBuffer(nil)
	vh.Write([]byte{0x00, 0x04})
	vh.WriteString("MQTT")
	vh.WriteByte(5)          // protocol level
	vh.WriteByte(0b00000010) // clean start
	binary.Write(vh, binary.BigEndian, uint16(mqttKeepAliveSeconds))
	vh.WriteByte(0x00) // properties length

	payload := encodeString(clientID)
	packet := buildPacket(0x10, vh.Bytes(), payload)
	return c.send(packet)
}

func (c *mqttClient) expectConnAck() error {
	pkt, err := c.recv()
	if err != nil {
		return err
	}
	if len(pkt) < 4 || pkt[0] != 0x20 {
		return fmt.Errorf("unexpected CONNACK: %x", pkt)
	}
	reason := pkt[len(pkt)-1]
	if reason != 0x00 {
		return fmt.Errorf("broker returned connect reason %d", reason)
	}
	return nil
}

func (c *mqttClient) subscribe(topic string, qos byte) error {
	c.pid++
	vh := bytes.NewBuffer(nil)
	binary.Write(vh, binary.BigEndian, c.pid)
	vh.WriteByte(0x00) // properties length

	payload := append(encodeString(topic), qos)
	packet := buildPacket(0x82, vh.Bytes(), payload)
	return c.send(packet)
}

func (c *mqttClient) expectSubAck() error {
	pkt, err := c.recv()
	if err != nil {
		return err
	}
	if len(pkt) < 5 || pkt[0] != 0x90 {
		return fmt.Errorf("unexpected SUBACK: %x", pkt)
	}
	reason := pkt[len(pkt)-1]
	if reason > 0x02 {
		return fmt.Errorf("subscription rejected (%d)", reason)
	}
	return nil
}

func (c *mqttClient) publish(topic string, payload []byte) error {
	vh := encodeString(topic)
	packet := buildPacket(0x30, vh, payload)
	return c.send(packet)
}

func (c *mqttClient) expectPublish(topic string, payload []byte) error {
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		pkt, err := c.recv()
		if err != nil {
			return err
		}
		if len(pkt) == 0 {
			continue
		}
		if pkt[0]&0xF0 != 0x30 {
			continue
		}
		remaining, consumed, err := decodeVarInt(pkt[1:])
		if err != nil {
			return err
		}
		body := pkt[1+consumed:]
		if len(body) < remaining {
			return errors.New("short publish packet")
		}
		msgTopic, rest, err := decodeString(body)
		if err != nil {
			return err
		}
		if msgTopic != topic {
			continue
		}
		if !bytes.Equal(rest, payload) {
			return fmt.Errorf("publish payload mismatch: got %q", string(rest))
		}
		return nil
	}
	return errors.New("publish not received before timeout")
}

func (c *mqttClient) send(packet []byte) error {
	_, _, err := c.stream.Send(c.ctx, packet, nil, nil)
	return err
}

func (c *mqttClient) recv() ([]byte, error) {
	chunk, err := c.stream.Recv(c.ctx, &cnd.RecvOptions{MaxBytes: 4096})
	if err != nil {
		return nil, err
	}
	if chunk == nil || chunk.Data == nil {
		return nil, io.EOF
	}
	data := append([]byte(nil), chunk.Data.Bytes()...)
	chunk.Data.Release()
	return data, nil
}

func buildPacket(packetType byte, vh, payload []byte) []byte {
	remaining := len(vh) + len(payload)
	buf := bytes.NewBuffer(nil)
	buf.WriteByte(packetType)
	buf.Write(encodeVarInt(remaining))
	buf.Write(vh)
	buf.Write(payload)
	return buf.Bytes()
}

func encodeString(s string) []byte {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.BigEndian, uint16(len(s)))
	buf.WriteString(s)
	return buf.Bytes()
}

func decodeString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, errors.New("insufficient data for string")
	}
	size := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+size {
		return "", nil, errors.New("short string data")
	}
	return string(b[2 : 2+size]), b[2+size:], nil
}

func encodeVarInt(x int) []byte {
	var out []byte
	for {
		encoded := byte(x % 128)
		x /= 128
		if x > 0 {
			encoded |= 128
		}
		out = append(out, encoded)
		if x == 0 {
			break
		}
	}
	return out
}

func decodeVarInt(b []byte) (int, int, error) {
	var multiplier = 1
	var value int
	var consumed int
	for {
		if consumed >= len(b) {
			return 0, consumed, errors.New("malformed varint")
		}
		encoded := int(b[consumed])
		consumed++
		value += (encoded & 127) * multiplier
		if encoded&128 == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, consumed, errors.New("varint too large")
		}
	}
	return value, consumed, nil
}
