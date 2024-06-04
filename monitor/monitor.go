package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/topology"
	"github.com/vishvananda/netlink"
)

// #include "../monitor.h"
import "C"

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

func SerializePath(from *HerculesPathHeader, ifid int) []byte {
	fmt.Println("serialize")
	out := make([]byte, 0, 1500)
	fmt.Println(out)
	out = binary.LittleEndian.AppendUint16(out, from.PartialChecksum)
	out = binary.LittleEndian.AppendUint16(out, uint16(ifid))
	fmt.Println(out)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(from.Header)))
	if len(from.Header) > C.HERCULES_MAX_HEADERLEN {
		// Header does not fit in the C struct
		fmt.Println("!! Header too long !!")
		// TODO This will panic in the below call to bytes.Repeat(), do something more appropriate
	}
	fmt.Println(out)
	out = append(out, from.Header...)
	out = append(out, bytes.Repeat([]byte{0x00}, C.HERCULES_MAX_HEADERLEN-len(from.Header))...)
	fmt.Println("Serialized header", out, len(out))
	fmt.Printf("hex header % x\n", out)
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

func headersToDestination(transfer HerculesTransfer) (int, []byte) {
	fmt.Println("making headers", transfer.pm.src, transfer.dest, transfer.nPaths)
	srcA := addr.Addr{
		IA:   localAddress.IA,
		Host: addr.MustParseHost(localAddress.Host.IP.String()),
	}
	dstA := addr.Addr{
		IA:   transfer.dest.IA,
		Host: addr.MustParseHost(transfer.dest.Host.IP.String()),
	}
	transfer.pm.choosePaths()
	paths := transfer.pm.dst.paths
	enabledPaths := []PathMeta{}
	for _, p := range paths {
		if p.enabled {
			enabledPaths = append(enabledPaths, p)
		}
	}
	numSelectedPaths := len(enabledPaths)
	headers_ser := []byte{}
	for _, p := range enabledPaths {
		preparedHeader := prepareHeader(p, transfer.mtu, *transfer.pm.src.Host, *transfer.dest.Host, srcA, dstA)
		headers_ser = append(headers_ser, SerializePath(&preparedHeader, p.iface.Index)...)
	}
	return numSelectedPaths, headers_ser
}

type TransferStatus int

const (
	Queued TransferStatus = iota
	Submitted
	Done
)

type HerculesTransfer struct {
	id     int            // ID identifying this transfer
	status TransferStatus // Status as seen by the monitor
	file   string         // Name of the file to transfer
	dest   snet.UDPAddr   // Destination
	mtu    int            // MTU to use
	nPaths int            // Maximum number of paths to use
	pm     *PathManager
	// The following two fields are meaningless if the job's status is 'Queued'
	state        C.enum_session_state // The state returned by the server
	err          C.enum_session_error // The error returned by the server
	time_elapsed int                  // Seconds the transfer has been running
	chunks_acked int                  // Number of successfully transferred chunks
}

var transfersLock sync.Mutex
var transfers = map[int]*HerculesTransfer{}
var nextID int = 1

// GET params:
// file (File to transfer)
// dest (Destination IA+Host)
func http_submit(w http.ResponseWriter, r *http.Request) {
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
	mtu := 1200
	if r.URL.Query().Has("mtu") {
		mtu, err = strconv.Atoi(r.URL.Query().Get("mtu"))
		if err != nil {
			io.WriteString(w, "parse err")
			return
		}
	}
	nPaths := 1
	if r.URL.Query().Has("np") {
		nPaths, err = strconv.Atoi(r.URL.Query().Get("np"))
		if err != nil {
			io.WriteString(w, "parse err")
			return
		}
	}
	fmt.Println(destParsed)
	destination := findPathRule(&pathRules, destParsed)
	pm, _ := initNewPathManager(interfaces, &destination, localAddress, uint64(mtu))
	transfersLock.Lock()
	jobid := nextID
	transfers[nextID] = &HerculesTransfer{
		id:     nextID,
		status: Queued,
		file:   file,
		dest:   *destParsed,
		mtu:    mtu,
		nPaths: nPaths,
		pm:     pm,
	}
	nextID += 1
	transfersLock.Unlock()

	io.WriteString(w, fmt.Sprintf("OK %d\n", jobid))
}

// GET Params:
// id: An ID obtained by submitting a transfer
// Returns OK status state err seconds_elapsed chucks_acked
func http_status(w http.ResponseWriter, r *http.Request) {
	if !r.URL.Query().Has("id") {
		io.WriteString(w, "missing parameter")
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		return
	}
	transfersLock.Lock()
	info, ok := transfers[id]
	transfersLock.Unlock()
	if !ok {
		return
	}
	io.WriteString(w, fmt.Sprintf("OK %d %d %d %d %d\n", info.status, info.state, info.err, info.time_elapsed, info.chunks_acked))
}

var localAddress *snet.UDPAddr
var interfaces []*net.Interface

type HostConfig struct {
	HostAddr addr.Addr
	NumPaths int
	PathSpec []PathSpec
}
type ASConfig struct {
	IA       addr.IA
	NumPaths int
	PathSpec []PathSpec
}

type MonitorConfig struct {
	DestinationHosts []HostConfig
	DestinationASes  []ASConfig
	DefaultNumPaths  int
}

type PathRules struct {
	Hosts           map[addr.Addr]HostConfig
	ASes            map[addr.IA]ASConfig
	DefaultNumPaths int
}

var config MonitorConfig
var pathRules PathRules = PathRules{}

func findPathRule(p *PathRules, dest *snet.UDPAddr) Destination {
	a := addr.Addr{
		IA:   dest.IA,
		Host: addr.MustParseHost(dest.Host.IP.String()),
	}
	confHost, ok := p.Hosts[a]
	if ok {
		return Destination{
			hostAddr: dest,
			pathSpec: &confHost.PathSpec,
			numPaths: confHost.NumPaths,
		}
	}
	conf, ok := p.ASes[dest.IA]
	if ok {
		return Destination{
			hostAddr: dest,
			pathSpec: &conf.PathSpec,
			numPaths: conf.NumPaths,
		}
	}
	return Destination{
		hostAddr: dest,
		pathSpec: &[]PathSpec{},
		numPaths: p.DefaultNumPaths,
	}
}

func main() {
	var localAddr string
	var configFile string
	flag.StringVar(&localAddr, "l", "", "local address")
	flag.StringVar(&configFile, "c", "herculesmon.conf", "Path to the monitor configuration file")
	flag.Parse()

	meta, err := toml.DecodeFile(configFile, &config)
	if err != nil {
		fmt.Printf("Error reading configuration file (%v): %v\n", configFile, err)
		os.Exit(1)
	}
	if len(meta.Undecoded()) > 0 {
		fmt.Printf("Unknown element(s) in config file: %v\n", meta.Undecoded())
		os.Exit(1)
	}
	// TODO Would be nice not to have to do this dance and specify the maps directly in the config file,
	// but the toml package crashes if the keys are addr.Addr
	if config.DefaultNumPaths == 0 {
		fmt.Println("Config: Default number of paths to use not set, using 1.")
		config.DefaultNumPaths = 1
	}
	pathRules.Hosts = map[addr.Addr]HostConfig{}
	for _, host := range config.DestinationHosts {
		numpaths := config.DefaultNumPaths
		if host.NumPaths != 0 {
			numpaths = host.NumPaths
		}
		pathspec := []PathSpec{}
		if host.PathSpec != nil {
			pathspec = host.PathSpec
		}
		pathRules.Hosts[host.HostAddr] = HostConfig{
			HostAddr: host.HostAddr,
			NumPaths: numpaths,
			PathSpec: pathspec,
		}
	}
	pathRules.ASes = map[addr.IA]ASConfig{}
	for _, as := range config.DestinationASes {
		numpaths := config.DefaultNumPaths
		if as.NumPaths != 0 {
			numpaths = as.NumPaths
		}
		pathspec := []PathSpec{}
		if as.PathSpec != nil {
			pathspec = as.PathSpec
		}
		pathRules.ASes[as.IA] = ASConfig{
			IA:       as.IA,
			NumPaths: numpaths,
			PathSpec: pathspec,
		}
	}
	pathRules.DefaultNumPaths = config.DefaultNumPaths

	src, err := snet.ParseUDPAddr(localAddr)
	if err != nil || src.Host.Port == 0 {
		flag.Usage()
		os.Exit(1)
	}
	localAddress = src
	GlobalQuerier = newPathQuerier()

	// TODO make socket paths congfigurable
	daemon, err := net.ResolveUnixAddr("unixgram", "/var/hercules.sock")
	fmt.Println(daemon, err)
	local, err := net.ResolveUnixAddr("unixgram", "/var/herculesmon.sock")
	fmt.Println(local, err)
	os.Remove("/var/herculesmon.sock")
	usock, err := net.ListenUnixgram("unixgram", local)
	fmt.Println(usock, err)

	ifs, _ := net.Interfaces()
	iffs := []*net.Interface{}
	for i, _ := range ifs {
		iffs = append(iffs, &ifs[i])
	}
	interfaces = iffs

	// used for looking up reply path interface
	pm, err := initNewPathManager(iffs, &Destination{
		hostAddr: localAddress,
	}, src, 0)
	fmt.Println(err)

	http.HandleFunc("/submit", http_submit)
	http.HandleFunc("/status", http_status)
	go http.ListenAndServe(":8000", nil)

	// TODO remove finished sessions after a while
	for {
		buf := make([]byte, C.SOCKMSG_SIZE)
		fmt.Println("read...", C.SOCKMSG_SIZE)
		n, a, err := usock.ReadFromUnix(buf)
		fmt.Println(n, a, err, buf)
		if n > 0 {
			msgtype := binary.LittleEndian.Uint16(buf[:2])
			buf = buf[2:]
			switch msgtype {
			case C.SOCKMSG_TYPE_GET_REPLY_PATH:
				fmt.Println("reply path")
				sample_len := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
				etherlen := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
				fmt.Println("smaple len", sample_len)
				replyPath, nextHop, err := getReplyPathHeader(buf[:sample_len], int(etherlen))
				iface, _ := pm.interfaceForRoute(nextHop)
				fmt.Println("reply iface", iface)
				fmt.Println(replyPath, err)
				b := SerializePath(replyPath, iface.Index)
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_GET_NEW_JOB:
				transfersLock.Lock()
				var selectedJob *HerculesTransfer = nil
				for _, job := range transfers {
					if job.status == 0 {
						selectedJob = job
						job.status = Submitted
						break
					}
				}
				transfersLock.Unlock()
				var b []byte
				if selectedJob != nil {
					fmt.Println("sending file to daemon:", selectedJob.file, selectedJob.id)
					// TODO Conversion between go and C strings?
					strlen := len(selectedJob.file)
					b = append(b, 1)
					b = binary.LittleEndian.AppendUint16(b, uint16(selectedJob.id))
					b = binary.LittleEndian.AppendUint16(b, uint16(selectedJob.mtu))
					b = binary.LittleEndian.AppendUint16(b, uint16(strlen))
					b = append(b, []byte(selectedJob.file)...)
					fmt.Println(b)
				} else {
					fmt.Println("no new jobs")
					b = append(b, 0)
				}
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_GET_PATHS:
				job_id := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
				fmt.Println("fetch path, job", job_id)
				transfersLock.Lock()
				job, _ := transfers[int(job_id)]
				n_headers, headers := headersToDestination(*job)
				transfersLock.Unlock()
				b := binary.LittleEndian.AppendUint16(nil, uint16(n_headers))
				b = append(b, headers...)
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_UPDATE_JOB:
				job_id := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
				status := binary.LittleEndian.Uint32(buf[:4])
				buf = buf[4:]
				errorcode := binary.LittleEndian.Uint32(buf[:4])
				buf = buf[4:]
				seconds := binary.LittleEndian.Uint64(buf[:8])
				buf = buf[8:]
				bytes_acked := binary.LittleEndian.Uint64(buf[:8])
				buf = buf[8:]
				fmt.Println("updating job", job_id, status, errorcode)
				transfersLock.Lock()
				job, _ := transfers[int(job_id)]
				job.state = status
				job.err = errorcode
				if (job.state == C.SESSION_STATE_DONE){
					job.status = Done
				}
				job.chunks_acked = int(bytes_acked) // FIXME
				job.time_elapsed = int(seconds)
				fmt.Println(job, job.state)
				transfersLock.Unlock()
				b := binary.LittleEndian.AppendUint16(nil, uint16(1))
				usock.WriteToUnix(b, a)

			default:
				fmt.Println("unknown message?")
			}
		}
	}
}
