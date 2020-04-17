// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// #cgo CFLAGS: -std=c11 -O3 -Wall -DNDEBUG -D_GNU_SOURCE -march=broadwell -mtune=broadwell
// #cgo LDFLAGS: ${SRCDIR}/bpf/libbpf.a -lm -lelf -pthread
// #pragma GCC diagnostic ignored "-Wunused-variable" // Hide warning in cgo-gcc-prolog
// #include "hercules.h"
// #include <linux/if_xdp.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/inconshreveable/log15"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/vishvananda/netlink"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// HerculesGetReplyPath creates a reply path header for the packet header in headerPtr with given length.
// Returns 0 iff successful.
// This function is exported to C and called to obtain a reply path to send NACKs from the receiver (slow path).
//export HerculesGetReplyPath
func HerculesGetReplyPath(headerPtr unsafe.Pointer, length C.int, replyPathStruct *C.struct_hercules_path) C.int {
	buf := C.GoBytes(headerPtr, length)
	replyPath, err := getReplyPathHeader(buf, activeInterface)
	if err != nil {
		log.Debug("HerculesGetReplyPath", "err", err)
		return 1
	}
	toCPath(*replyPath, replyPathStruct, false, false)
	return 0
}

func getReplyPathHeader(buf []byte, iface *net.Interface) (*HerculesPath, error) {
	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		return nil, fmt.Errorf("Error decoding some part of the packet: %v", err)
	}
	ip4 := packet.Layer(layers.LayerTypeIPv4)
	if ip4 == nil {
		return nil, errors.New("Error decoding IPv4 layer")
	}
	dstIP, srcIP := ip4.(*layers.IPv4).SrcIP, ip4.(*layers.IPv4).DstIP

	udp := packet.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return nil, errors.New("Error decoding IPv4/UDP layer")
	}
	udpPayload := udp.(*layers.UDP).Payload
	udpDstPort, _ := udp.(*layers.UDP).SrcPort, udp.(*layers.UDP).DstPort

	if len(udpPayload) < 8 { // Guard against bug in ParseScnPkt
		return nil, errors.New("Error decoding SCION packet: payload too small")
	}

	var scionPkt spkt.ScnPkt
	// XXX: ignore checksum errors. No API to parse without payload validation
	if err := hpkt.ParseScnPkt(&scionPkt, udpPayload); err != nil {
		return nil, fmt.Errorf("Error decoding SCION packet: %v", err)
	}

	scionPkt.DstIA, scionPkt.SrcIA = scionPkt.SrcIA, scionPkt.DstIA
	scionPkt.DstHost, scionPkt.SrcHost = scionPkt.SrcHost, scionPkt.DstHost

	if scionPkt.Path != nil {
		if err := scionPkt.Path.Reverse(); err != nil {
			return nil, fmt.Errorf("Failed to reverse SCION path: %v", err)
		}
		log.Debug("getReplyPathHeader", "path", scionPkt.Path)
	} else {
		log.Debug("getReplyPathHeader", "path", "No SCION Path header, source and destination in same AS.")
	}

	if scionPkt.L4 == nil {
		return nil, errors.New("Error decoding SCION/UDP")
	}
	scionPkt.L4.Reverse()

	overlayHeader, err := prepareOverlayPacketHeader(srcIP, dstIP, uint16(udpDstPort), iface)

	scionHeaderLen := scionPkt.HdrLen() + l4.UDPLen
	payloadLen := etherLen - len(overlayHeader) - scionHeaderLen
	scionPkt.Pld = common.RawBytes(make([]byte, payloadLen))

	scionHeader := make([]byte, etherLen)
	_, err = hpkt.WriteScnPkt(&scionPkt, scionHeader) // XXX: writes bogus L4 checksum
	if err != nil {
		return nil, err
	}
	scionHeader = scionHeader[:scionHeaderLen]
	scionChecksum := binary.LittleEndian.Uint16(scionPkt.L4.GetCSum())
	headerBuf := append(overlayHeader, scionHeader...)
	herculesPath := HerculesPath{
		Header:          headerBuf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, nil
}

func toCPath(from HerculesPath, to *C.struct_hercules_path, replaced, enabled bool) {
	if len(from.Header) > C.HERCULES_MAX_HEADERLEN {
		panic(fmt.Sprintf("Header too long (%d), can't invoke hercules C API.", len(from.Header)))
	}
	to.headerlen = C.int(len(from.Header))
	to.payloadlen = C.int(etherLen - len(from.Header)) // TODO(matzf): take actual MTU into account, also when building header
	to.framelen = C.int(etherLen)                      // TODO(matzf): "
	// XXX(matzf): is there a nicer way to do this?
	C.memcpy(unsafe.Pointer(&to.header[0]),
		unsafe.Pointer(&from.Header[0]),
		C.ulong(len(from.Header)))
	to.checksum = C.ushort(from.PartialChecksum)
	to.replaced = C.atomic_bool(replaced)
	to.enabled = C.atomic_bool(enabled)
	to.max_bps = 0
}

func toCAddr(in *snet.UDPAddr) C.struct_hercules_app_addr {

	bufIA := make([]byte, 8)
	in.IA.Write(bufIA)
	bufIP := in.Host.IP.To4()
	bufPort := make([]byte, 2)
	binary.BigEndian.PutUint16(bufPort, uint16(in.Host.Port))

	out := C.struct_hercules_app_addr{}
	C.memcpy(unsafe.Pointer(&out.ia), unsafe.Pointer(&bufIA[0]), 8)
	C.memcpy(unsafe.Pointer(&out.ip), unsafe.Pointer(&bufIP[0]), 4)
	C.memcpy(unsafe.Pointer(&out.port), unsafe.Pointer(&bufPort[0]), 2)
	return out
}

func prepareSCIONPacketHeader(src, dst *snet.UDPAddr, iface *net.Interface) (*HerculesPath, error) {

	overlayHeader, err := prepareOverlayPacketHeader(src.Host.IP, dst.NextHop.IP, uint16(dst.NextHop.Port), iface)
	if err != nil {
		return nil, err
	}

	scionPkt := &spkt.ScnPkt{
		DstIA:   dst.IA,
		SrcIA:   src.IA,
		DstHost: addr.HostFromIP(dst.Host.IP),
		SrcHost: addr.HostFromIP(src.Host.IP),
		Path:    dst.Path,
		L4: &l4.UDP{
			SrcPort: uint16(src.Host.Port),
			DstPort: uint16(dst.Host.Port),
		},
	}
	scionHeaderLen := scionPkt.HdrLen() + l4.UDPLen
	payloadLen := etherLen - len(overlayHeader) - scionHeaderLen
	scionPkt.Pld = common.RawBytes(make([]byte, payloadLen))

	scionHeader := make([]byte, etherLen)
	_, err = hpkt.WriteScnPkt(scionPkt, scionHeader) // XXX: writes bogus L4 checksum
	if err != nil {
		return nil, err
	}
	scionHeader = scionHeader[:scionHeaderLen]
	scionChecksum := binary.LittleEndian.Uint16(scionPkt.L4.GetCSum())
	buf := append(overlayHeader, scionHeader...)
	herculesPath := HerculesPath{
		Header:          buf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, nil
}

func prepareOverlayPacketHeader(srcIP, dstIP net.IP, dstPort uint16, iface *net.Interface) ([]byte, error) {
	dstMAC, srcMAC, err := getAddrs(iface, dstIP)
	if err != nil {
		return nil, err
	}

	ethHeader := 14
	ipHeader := 20
	udpHeader := 8

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:    4,
		IHL:        5, // Computed at serialization when FixLengths option set
		TOS:        0x0,
		Length:     uint16(etherLen - ethHeader), // Computed at serialization when FixLengths option set
		Id:         0,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        0xFF,
		Protocol:   layers.IPProtocolUDP,
		//Checksum: 0, // Set at serialization with the ComputeChecksums option
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Options: nil,
	}

	srcPort := uint16(topology.EndhostPort)
	udp := layers.UDP{
		SrcPort:  layers.UDPPort(srcPort),
		DstPort:  layers.UDPPort(dstPort),
		Length:   uint16(etherLen - ethHeader - ipHeader),
		Checksum: 0,
	}

	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}
	serializeOptsChecked := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}
	err = serializeLayersWOpts(buf,
		layerWithOpts{&eth, serializeOpts},
		layerWithOpts{&ip, serializeOptsChecked},
		layerWithOpts{&udp, serializeOpts})
	if err != nil {
		return nil, err
	}

	// return only the headers
	return buf.Bytes()[:ethHeader+ipHeader+udpHeader], nil
}

func serializeLayersWOpts(w gopacket.SerializeBuffer, layersWOpts ...layerWithOpts) error {
	w.Clear()
	for i := len(layersWOpts) - 1; i >= 0; i-- {
		layerWOpt := layersWOpts[i]
		err := layerWOpt.Layer.SerializeTo(w, layerWOpt.Opts)
		if err != nil {
			return err
		}
		w.PushLayer(layerWOpt.Layer.LayerType())
	}
	return nil
}

// getAddrs returns dstMAC, srcMAC and srcIP for a packet to be sent over interface to destination.
func getAddrs(iface *net.Interface, destination net.IP) (dstMAC, srcMAC net.HardwareAddr, err error) {

	srcMAC = iface.HardwareAddr

	// Get destination MAC (address of either destination or gateway) using netlink
	// n is the handle (i.e. the main entrypoint) for netlink
	n, err := netlink.NewHandle()
	if err != nil {
		return
	}
	defer n.Delete()

	routes, err := n.RouteGet(destination)
	if err != nil {
		return
	}
	route := routes[0]
	for _, r := range routes {
		if r.LinkIndex == iface.Index {
			route = r
			break
		}
	}
	if route.LinkIndex != iface.Index {
		err = errors.New("No route found to destination on specified interface")
	}

	dstIP := destination
	if route.Gw != nil {
		dstIP = route.Gw
	}
	dstMAC, err = getNeighborMAC(n, iface.Index, dstIP)
	if err != nil {
		if err.Error() == "Missing ARP entry" {
			// Handle missing ARP entry
			fmt.Printf("Sending ICMP echo to %v over %v and retrying...\n", dstIP, iface.Name)

			// Send ICMP
			if err = sendICMP(iface, route.Src, dstIP); err != nil {
				return
			}
			// Poll for 3 seconds
			for start := time.Now(); time.Since(start) < time.Duration(3)*time.Second; {
				dstMAC, err = getNeighborMAC(n, iface.Index, dstIP)
				if err == nil {
					break
				}
			}
		}
		if err != nil {
			return
		}
	}

	return
}

// getNeighborMAC returns the HardwareAddr for the neighbor (ARP table entry) with the given IP
func getNeighborMAC(n *netlink.Handle, linkIndex int, ip net.IP) (net.HardwareAddr, error) {
	neighbors, err := n.NeighList(linkIndex, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	for _, neigh := range neighbors {
		if neigh.IP.Equal(ip) && neigh.HardwareAddr != nil {
			return neigh.HardwareAddr, nil
		}
	}
	return nil, errors.New("Missing ARP entry")
}

func sendICMP(iface *net.Interface, srcIP net.IP, dstIP net.IP) (err error) {
	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoRequest,
	}
	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, serializeOpts, &ip, &icmp)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Println("Creating raw socket failed.")
		return err
	}
	defer syscall.Close(fd)
	dstIPRaw := [4]byte{}
	copy(dstIPRaw[:4], dstIP.To4())
	ipSockAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: dstIPRaw,
	}
	if err = syscall.Sendto(fd, buf.Bytes(), 0, &ipSockAddr); err != nil {
		fmt.Printf("Sending ICMP echo to %v over %v failed.\n", dstIP, iface.Name)
		return err
	}
	return nil
}
