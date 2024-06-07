package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology"
	"github.com/vishvananda/netlink"
)

type layerWithOpts struct {
	Layer gopacket.SerializableLayer
	Opts  gopacket.SerializeOptions
}

func prepareUnderlayPacketHeader(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort uint16, etherLen int) ([]byte, error) {
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
	err := serializeLayersWOpts(buf,
		layerWithOpts{&eth, serializeOpts},
		layerWithOpts{&ip, serializeOptsChecked},
		layerWithOpts{&udp, serializeOpts})
	if err != nil {
		return nil, err
	}

	// return only the header
	return buf.Bytes()[:ethHeader+ipHeader+udpHeader], nil
}

func serializeLayersWOpts(w gopacket.SerializeBuffer, layersWOpts ...layerWithOpts) error {
	err := w.Clear()
	if err != nil {
		return err
	}
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

// Determine the reply path by reversing the path of a received packet
func getReplyPathHeader(buf []byte, etherLen int) (*HerculesPathHeader, net.IP, error) {
	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		return nil, nil, fmt.Errorf("error decoding some part of the packet: %v", err)
	}
	eth := packet.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return nil, nil, errors.New("error decoding ETH layer")
	}
	dstMAC, srcMAC := eth.(*layers.Ethernet).SrcMAC, eth.(*layers.Ethernet).DstMAC

	ip4 := packet.Layer(layers.LayerTypeIPv4)
	if ip4 == nil {
		return nil, nil, errors.New("error decoding IPv4 layer")
	}
	dstIP, srcIP := ip4.(*layers.IPv4).SrcIP, ip4.(*layers.IPv4).DstIP

	udp := packet.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return nil, nil, errors.New("error decoding IPv4/UDP layer")
	}
	udpPayload := udp.(*layers.UDP).Payload
	udpDstPort := udp.(*layers.UDP).SrcPort

	if len(udpPayload) < 8 { // Guard against bug in ParseScnPkt
		return nil, nil, errors.New("error decoding SCION packet: payload too small")
	}

	sourcePkt := snet.Packet{
		Bytes: udpPayload,
	}
	if err := sourcePkt.Decode(); err != nil {
		return nil, nil, fmt.Errorf("error decoding SCION packet: %v", err)
	}

	rpath, ok := sourcePkt.Path.(snet.RawPath)
	if !ok {
		return nil, nil, fmt.Errorf("error decoding SCION packet: unexpected dataplane path type")
	}
	if len(rpath.Raw) != 0 {
		replyPath, err := snet.DefaultReplyPather{}.ReplyPath(rpath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to reverse SCION path: %v", err)
		}
		sourcePkt.Path = replyPath
	}

	udpPkt, ok := sourcePkt.Payload.(snet.UDPPayload)
	if !ok {
		return nil, nil, errors.New("error decoding SCION/UDP")
	}

	if sourcePkt.Source.IA == sourcePkt.Destination.IA {
		sourcePkt.Path = path.Empty{}
	}

	underlayHeader, err := prepareUnderlayPacketHeader(srcMAC, dstMAC, srcIP, dstIP, uint16(udpDstPort), etherLen)
	if err != nil {
		return nil, nil, err
	}

	payload := snet.UDPPayload{
		SrcPort: udpPkt.DstPort,
		DstPort: udpPkt.SrcPort,
		Payload: nil,
	}

	destPkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: sourcePkt.Source,
			Source:      sourcePkt.Destination,
			Path:        sourcePkt.Path,
			Payload:     payload,
		},
	}

	if err = destPkt.Serialize(); err != nil {
		return nil, nil, err
	}
	scionHeaderLen := len(destPkt.Bytes)
	payloadLen := etherLen - len(underlayHeader) - scionHeaderLen
	payload.Payload = make([]byte, payloadLen)
	destPkt.Payload = payload

	if err = destPkt.Serialize(); err != nil {
		return nil, nil, err
	}
	scionHeader := destPkt.Bytes[:scionHeaderLen]
	scionChecksum := binary.BigEndian.Uint16(scionHeader[scionHeaderLen-2:])
	headerBuf := append(underlayHeader, scionHeader...)
	herculesPath := HerculesPathHeader{
		Header:          headerBuf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, dstIP, nil
}

func SerializePath(from *HerculesPathHeader, ifid int, maxHeaderLen int) []byte {
	out := []byte{}
	out = binary.LittleEndian.AppendUint16(out, from.PartialChecksum)
	out = binary.LittleEndian.AppendUint16(out, uint16(ifid))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(from.Header)))
	if len(from.Header) > maxHeaderLen {
		// Header does not fit in the C struct
		return nil
	}
	out = append(out, from.Header...)
	out = append(out, bytes.Repeat([]byte{0x00}, maxHeaderLen-len(from.Header))...)
	return out
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
		err = errors.New("no route found to destination on specified interface")
	}

	dstIP := destination
	if route.Gw != nil {
		dstIP = route.Gw
	}
	dstMAC, err = getNeighborMAC(n, iface.Index, dstIP)
	if err != nil {
		if err.Error() == "missing ARP entry" {
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

func sendICMP(iface *net.Interface, srcIP net.IP, dstIP net.IP) (err error) {
	icmp := layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoRequest,
	}
	buf := gopacket.NewSerializeBuffer()
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, serializeOpts, &icmp)
	if err != nil {
		return err
	}

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
	return nil, errors.New("missing ARP entry")
}

// TODO no reason to pass in both net.udpaddr and addr.Addr, but the latter does not include the port
func prepareHeader(path PathMeta, etherLen int, srcUDP, dstUDP net.UDPAddr, srcAddr, dstAddr addr.Addr) HerculesPathHeader {
	iface := path.iface
	dstMAC, srcMAC, err := getAddrs(iface, path.path.UnderlayNextHop().IP)
	fmt.Println(dstMAC, srcMAC, err)

	underlayHeader, err := prepareUnderlayPacketHeader(srcMAC, dstMAC, srcUDP.IP, path.path.UnderlayNextHop().IP, uint16(path.path.UnderlayNextHop().Port), etherLen)
	fmt.Println(underlayHeader, err)

	payload := snet.UDPPayload{
		SrcPort: srcUDP.AddrPort().Port(),
		DstPort: dstUDP.AddrPort().Port(),
		Payload: nil,
	}

	destPkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: dstAddr,
			Source:      srcAddr,
			Path:        path.path.Dataplane(),
			Payload:     payload,
		},
	}

	if err = destPkt.Serialize(); err != nil {
		fmt.Println("serializer err")
	}
	scionHeaderLen := len(destPkt.Bytes)
	payloadLen := etherLen - len(underlayHeader) - scionHeaderLen
	payload.Payload = make([]byte, payloadLen)
	destPkt.Payload = payload

	if err = destPkt.Serialize(); err != nil {
		fmt.Println("serrializer err2")
	}
	scionHeader := destPkt.Bytes[:scionHeaderLen]
	scionChecksum := binary.BigEndian.Uint16(scionHeader[scionHeaderLen-2:])
	headerBuf := append(underlayHeader, scionHeader...)
	herculesPath := HerculesPathHeader{
		Header:          headerBuf,
		PartialChecksum: scionChecksum,
	}
	fmt.Println(herculesPath)
	return herculesPath
}
