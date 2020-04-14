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

package udp_icmp_error_propagation_test

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

type connected bool

func (c connected) String() string {
	if c {
		return "Connected"
	}
	return "Connectionless"
}

type icmpError int

const (
	portUnreachable icmpError = iota
	timeToLiveExceeded
)

func (e icmpError) String() string {
	switch e {
	case portUnreachable:
		return "PortUnreachable"
	case timeToLiveExceeded:
		return "TimeToLiveExpired"
	}
	return "Unknown ICMP error"
}

func (e icmpError) ToICMPv4() *tb.ICMPv4 {
	switch e {
	case portUnreachable:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4DstUnreachable), Code: tb.Uint8(header.ICMPv4PortUnreachable)}
	case timeToLiveExceeded:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4TimeExceeded), Code: tb.Uint8(header.ICMPv4TTLExceeded)}
	}
	return nil
}

// testCommon executes logic common to all subtests: connect the UDP socket on
// the DUT if needed, send a UDP datagram through it, and inject an ICMP error
// response containing the IP and UDP headers of the datagram that was sent.
func testCommon(t *testing.T, dut *tb.DUT, conn *tb.UDPIPv4, remoteFd int32, c connected, icmpError icmpError) {
	if c {
		dut.Connect(remoteFd, conn.LocalAddr())
	}

	dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
	udp, err := conn.Expect(tb.UDP{}, time.Second)
	if err != nil {
		t.Fatalf("did not receive message from DUT: %s", err)
	}

	if icmpError == timeToLiveExceeded {
		ip, ok := udp.Prev().(*tb.IPv4)
		if !ok {
			t.Fatalf("expected %s to be IPv4", udp.Prev())
		}
		*ip.TTL = 1
		// Let serialization recalculate the checksum since we set the
		// TTL to 1.
		ip.Checksum = nil

		// Note that the ICMP payload is valid in this case because the UDP
		// payload is empty. If the UDP payload were not empty, the packet
		// length during serialization may not be calculated correctly,
		// resulting in a mal-formed packet.
		conn.SendIP(icmpError.ToICMPv4(), ip, udp)
	} else {
		conn.SendIP(icmpError.ToICMPv4(), udp.Prev(), udp)
	}
}

func testRecv(t *testing.T, c connected, icmpError icmpError, expected syscall.Errno) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()

	remoteFd, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(remoteFd)

	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()

	testCommon(t, &dut, &conn, remoteFd, c, icmpError)

	conn.Send(tb.UDP{})

	if expected != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ret, _, err := dut.RecvWithErrno(ctx, remoteFd, 100, 0)
		if ret != -1 {
			t.Fatalf("recv after ICMP error succeeded unexpectedly")
		}
		if err != expected {
			t.Fatalf("recv after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, expected)
		}
	}

	dut.Recv(remoteFd, 100, 0)
}

func testSendTo(t *testing.T, c connected, icmpError icmpError, expected syscall.Errno) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()

	remoteFd, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(remoteFd)

	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()

	testCommon(t, &dut, &conn, remoteFd, c, icmpError)

	if expected != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ret, err := dut.SendToWithErrno(ctx, remoteFd, nil, 0, conn.LocalAddr())

		if ret != -1 {
			t.Fatalf("sendto after ICMP error succeeded unexpectedly")
		}
		if err != expected {
			t.Fatalf("sendto after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, expected)
		}
	}

	dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
	if _, err := conn.Expect(tb.UDP{}, time.Second); err != nil {
		t.Fatalf("did not receive UDP packet as expected: %s", err)
	}
}

func testSockOpt(t *testing.T, c connected, icmpError icmpError, expected syscall.Errno) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()

	remoteFd, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(remoteFd)

	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()

	testCommon(t, &dut, &conn, remoteFd, c, icmpError)

	errno := syscall.Errno(dut.GetSockOptInt(remoteFd, unix.SOL_SOCKET, unix.SO_ERROR))
	if errno != expected {
		t.Fatalf("SO_ERROR sockopt after ICMP error is (%[1]d) %[1]v, expected (%[2]d) %[2]v", errno, expected)
	}

	// Check that after clearing socket error, sending doesn't fail.
	dut.SendTo(remoteFd, nil, 0, conn.LocalAddr())
	if _, err := conn.Expect(tb.UDP{}, time.Second); err != nil {
		t.Fatalf("did not receive UDP packet as expected: %s", err)
	}
}

func TestUdpIcmpErrorPropagation(t *testing.T) {
	for _, tt := range []struct {
		c     connected
		i     icmpError
		errno syscall.Errno
	}{
		{true, portUnreachable, unix.ECONNREFUSED},
		{false, portUnreachable, syscall.Errno(0)},
		{true, timeToLiveExceeded, syscall.Errno(0)},
		{false, timeToLiveExceeded, syscall.Errno(0)},
	} {
		t.Run(fmt.Sprintf("%s%sSendTo", tt.c, tt.i), func(t *testing.T) {
			testSendTo(t, tt.c, tt.i, tt.errno)
		})
		t.Run(fmt.Sprintf("%s%sRecv", tt.c, tt.i), func(t *testing.T) {
			testRecv(t, tt.c, tt.i, tt.errno)
		})
		t.Run(fmt.Sprintf("%s%sSockOpt", tt.c, tt.i), func(t *testing.T) {
			testSockOpt(t, tt.c, tt.i, tt.errno)
		})
		// TODO(b/63594852) Once MSG_ERRQUEUE is supported, add
		// recvmsg as an error detection method.
	}
}
