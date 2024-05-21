package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	// "github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology"
	"github.com/vishvananda/netlink"
)

// #include "../monitor.h"
import "C"

// TODO should not be here
const etherLen = 1200

type layerWithOpts struct {
	Layer gopacket.SerializableLayer
	Opts  gopacket.SerializeOptions
}

func prepareUnderlayPacketHeader(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort uint16) ([]byte, error) {
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

func getReplyPathHeader(buf []byte) (*HerculesPathHeader, error) {
	packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		return nil, fmt.Errorf("error decoding some part of the packet: %v", err)
	}
	eth := packet.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return nil, errors.New("error decoding ETH layer")
	}
	dstMAC, srcMAC := eth.(*layers.Ethernet).SrcMAC, eth.(*layers.Ethernet).DstMAC

	ip4 := packet.Layer(layers.LayerTypeIPv4)
	if ip4 == nil {
		return nil, errors.New("error decoding IPv4 layer")
	}
	dstIP, srcIP := ip4.(*layers.IPv4).SrcIP, ip4.(*layers.IPv4).DstIP

	udp := packet.Layer(layers.LayerTypeUDP)
	if udp == nil {
		return nil, errors.New("error decoding IPv4/UDP layer")
	}
	udpPayload := udp.(*layers.UDP).Payload
	udpDstPort := udp.(*layers.UDP).SrcPort

	if len(udpPayload) < 8 { // Guard against bug in ParseScnPkt
		return nil, errors.New("error decoding SCION packet: payload too small")
	}

	sourcePkt := snet.Packet{
		Bytes: udpPayload,
	}
	if err := sourcePkt.Decode(); err != nil {
		return nil, fmt.Errorf("error decoding SCION packet: %v", err)
	}

	rpath, ok := sourcePkt.Path.(snet.RawPath)
	if !ok {
		return nil, fmt.Errorf("error decoding SCION packet: unexpected dataplane path type")
	}
	if len(rpath.Raw) != 0 {
		replyPath, err := snet.DefaultReplyPather{}.ReplyPath(rpath)
		if err != nil {
			return nil, fmt.Errorf("failed to reverse SCION path: %v", err)
		}
		sourcePkt.Path = replyPath
	}

	sourcePkt.Path = path.Empty{}

	udpPkt, ok := sourcePkt.Payload.(snet.UDPPayload)
	if !ok {
		return nil, errors.New("error decoding SCION/UDP")
	}

	underlayHeader, err := prepareUnderlayPacketHeader(srcMAC, dstMAC, srcIP, dstIP, uint16(udpDstPort))
	if err != nil {
		return nil, err
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
		return nil, err
	}
	scionHeaderLen := len(destPkt.Bytes)
	payloadLen := etherLen - len(underlayHeader) - scionHeaderLen
	payload.Payload = make([]byte, payloadLen)
	destPkt.Payload = payload

	if err = destPkt.Serialize(); err != nil {
		return nil, err
	}
	scionHeader := destPkt.Bytes[:scionHeaderLen]
	scionChecksum := binary.BigEndian.Uint16(scionHeader[scionHeaderLen-2:])
	headerBuf := append(underlayHeader, scionHeader...)
	herculesPath := HerculesPathHeader{
		Header:          headerBuf,
		PartialChecksum: scionChecksum,
	}
	return &herculesPath, nil
}

func SerializePath(from *HerculesPathHeader) []byte {
	fmt.Println("serialize")
	out := make([]byte, 0, 1500)
	fmt.Println(out)
	out = binary.LittleEndian.AppendUint16(out, from.PartialChecksum)
	fmt.Println(out)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(from.Header)))
	fmt.Println(out)
	out = append(out, from.Header...)
	fmt.Println(out)
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

func getNewHeader() HerculesPathHeader {
	srcAddr := addr.MustParseAddr("17-ffaa:1:fe2,192.168.50.1")
	srcIP := net.ParseIP(srcAddr.Host.String())
	dstAddr := addr.MustParseAddr("17-ffaa:1:fe2,192.168.50.2")
	dstIP := net.ParseIP(dstAddr.Host.String())
	// querier := newPathQuerier()
	// path, err := querier.Query(context.Background(), dest)
	// fmt.Println(path, err)
	emptyPath := path.Empty{}

	iface, err := net.InterfaceByName("ens5f0")
	fmt.Println(iface, err)
	dstMAC, srcMAC, err := getAddrs(iface, dstIP)
	fmt.Println(dstMAC, srcMAC, err)
	fmt.Println(dstIP, srcIP)
	underlayHeader, err := prepareUnderlayPacketHeader(srcMAC, dstMAC, srcIP, dstIP, uint16(30041))
	fmt.Println(underlayHeader, err)

	payload := snet.UDPPayload{
		SrcPort: 123,
		DstPort: 123,
		Payload: nil,
	}

	destPkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: dstAddr,
			Source:      srcAddr,
			Path:        emptyPath,
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

type HerculesTransfer struct {
	id     int
	status int
	file   string
	dest   snet.UDPAddr
}

var transfersLock sync.Mutex
var transfers = map[int]*HerculesTransfer{}
var nextID int = 1

// GET params:
// file (File to transfer)
// dest (Destination IA+Host)
func httpreq(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r)
	if !r.URL.Query().Has("file") || !r.URL.Query().Has("dest") {
		io.WriteString(w, "missing parameter")
		return
	}
	file := r.URL.Query().Get("file")
	dest := r.URL.Query().Get("dest")
	fmt.Println(file, dest)
	destParsed, err := snet.ParseUDPAddr(dest)
	if err != nil {
		io.WriteString(w, "parse err")
		return
	}
	fmt.Println(destParsed)
	transfersLock.Lock()
	transfers[nextID] = &HerculesTransfer{
		id:     nextID,
		status: 0,
		file:   file,
		dest:   *destParsed,
	}
	nextID += 1
	transfersLock.Unlock()

	io.WriteString(w, "OK")
}

func main() {
	daemon, err := net.ResolveUnixAddr("unixgram", "/var/hercules.sock")
	fmt.Println(daemon, err)
	local, err := net.ResolveUnixAddr("unixgram", "/var/herculesmon.sock")
	fmt.Println(local, err)
	os.Remove("/var/herculesmon.sock")
	usock, err := net.ListenUnixgram("unixgram", local)
	fmt.Println(usock, err)

	http.HandleFunc("/", httpreq)
	go http.ListenAndServe(":8000", nil)

	for {
		buf := make([]byte, 2000)
		fmt.Println("read...")
		n, a, err := usock.ReadFromUnix(buf)
		fmt.Println(n, a, err, buf)
		if n > 0 {
			id := binary.LittleEndian.Uint16(buf[:2])
			buf = buf[2:]
			switch id {
			case C.SOCKMSG_TYPE_GET_REPLY_PATH:
				fmt.Println("reply path")
				sample_len := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
				replyPath, err := getReplyPathHeader(buf[:sample_len])
				fmt.Println(replyPath, err)
				b := SerializePath(replyPath)
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_GET_NEW_JOB:
				transfersLock.Lock()
				var selectedJob *HerculesTransfer = nil
				for _, job := range transfers {
					if job.status == 0 {
						selectedJob = job
						job.status = 1
						break
					}
				}
				transfersLock.Unlock()
				var b []byte
				if selectedJob != nil {
					fmt.Println("sending file to daemon", selectedJob.file)
					// TODO Conversion between go and C strings?
					strlen := len(selectedJob.file)
					b = append(b, 1)
					b = binary.LittleEndian.AppendUint16(b, uint16(selectedJob.id))
					b = binary.LittleEndian.AppendUint16(b, uint16(strlen))
					b = append(b, []byte(selectedJob.file)...)
					fmt.Println(b)
				} else {
					fmt.Println("no new jobs")
					b = append(b, 0)
				}
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_GET_PATHS:
				fmt.Println("fetch path")
				header := getNewHeader()
				b := binary.LittleEndian.AppendUint16(nil, uint16(1))
				b = append(b, SerializePath(&header)...)
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_UPDATE_JOB:
				fallthrough

			default:
				fmt.Println("unknown message?")
			}
		}
	}
}
