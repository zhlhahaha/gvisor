// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_send_window_segment_size_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

// TestSendWindowSegmentSizes does sanity checking of segment transmissions
// when the advertized receive window by the remote is close to the segment
// size.
func TestSendWindowSegmentSizes(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)

	sampleData := []byte("Sample Data")
	payloadSize := uint16(len(sampleData))

	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort, WindowSize: tb.Uint16(payloadSize)}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	conn.Handshake()
	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	dut.SetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	// Check if the segment that exactly fits in the receiver window.
	dut.Send(acceptFd, sampleData, 0)
	expectedTCP := tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}
	expectedPayload := tb.Payload{Bytes: sampleData}
	if _, err := conn.ExpectData(&expectedTCP, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected %v but didn't get one: %s", tb.Layers{&expectedTCP, &expectedPayload}, err)
	}

	// Check if the segment size is less than advertized receive window.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(payloadSize - 1)})
	dut.Send(acceptFd, sampleData, 0)
	expectedPayload = tb.Payload{Bytes: sampleData[:(payloadSize - 1)]}
	if _, err := conn.ExpectData(&expectedTCP, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected %v but didn't get one: %s", tb.Layers{&expectedTCP, &expectedPayload}, err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
	expectedPayload = tb.Payload{Bytes: sampleData[(payloadSize - 1):]}
	if _, err := conn.ExpectData(&expectedTCP, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected %v but didn't get one: %s", tb.Layers{&expectedTCP, &expectedPayload}, err)
	}

	// Check if the segment size is greater than advertized receive window.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(payloadSize + 1)})
	dut.Send(acceptFd, sampleData, 0)
	expectedPayload = tb.Payload{Bytes: sampleData}
	if _, err := conn.ExpectData(&expectedTCP, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected %v but didn't get one: %s", tb.Layers{&expectedTCP, &expectedPayload}, err)
	}
}
