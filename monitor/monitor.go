package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// #include "../monitor.h"
import "C"
const HerculesMaxPktsize = C.HERCULES_MAX_PKTSIZE

// Select paths and serialize headers for a given transfer
func headersToDestination(transfer HerculesTransfer) (int, []byte) {
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
		preparedHeader := prepareHeader(p, transfer.pm.mtu, *transfer.pm.src.Host, *transfer.dest.Host, srcA, dstA)
		serializedHeader := SerializePath(&preparedHeader, p.iface.Index, C.HERCULES_MAX_HEADERLEN)
		if serializedHeader == nil {
			fmt.Printf("Unable to serialize header for path: %v\n", p.path)
			numSelectedPaths--
			continue
		}
		headers_ser = append(headers_ser, serializedHeader...)
	}
	return numSelectedPaths, headers_ser
}

type TransferStatus int

const (
	Queued    TransferStatus = iota // Received by the monitor, enqueued, not yet known to the server
	Submitted                       // The server is processing the transfer
	Done                            // The server is done with the transfer (not necessarily successfully)
)
// Note that the monitor's transfer status is distinct from the server's session state.
// The monitor's status is used to distinguish queued jobs from ones already submitted to the server,
// since the server has no concept of pending jobs.

type HerculesTransfer struct {
	id     int            // ID identifying this transfer
	status TransferStatus // Status as seen by the monitor
	file   string         // Name of the file to transfer
	dest   snet.UDPAddr   // Destination
	pm     *PathManager
	// The following two fields are meaningless if the job's status is 'Queued'
	// They are updated when the server sends messages of type 'update_job'
	state        C.enum_session_state // The state returned by the server
	err          C.enum_session_error // The error returned by the server
	time_elapsed int                  // Seconds the transfer has been running
	chunks_acked int                  // Number of successfully transferred chunks
}

var transfersLock sync.Mutex // To protect the map below
var transfers = map[int]*HerculesTransfer{}
var nextID int = 1 // ID to use for the next transfer

var localAddress *snet.UDPAddr
var interfaces []*net.Interface

var pathRules PathRules

func main() {
	var localAddr string
	var configFile string
	flag.StringVar(&localAddr, "l", "", "local address")
	flag.StringVar(&configFile, "c", "herculesmon.conf", "Path to the monitor configuration file")
	flag.Parse()

	var config MonitorConfig
	config, pathRules = readConfig(configFile)
	fmt.Println(config)

	src, err := snet.ParseUDPAddr(localAddr)
	if err != nil || src.Host.Port == 0 {
		flag.Usage()
		os.Exit(1)
	}
	localAddress = src
	GlobalQuerier = newPathQuerier() // TODO can the connection time out?

	// TODO make socket paths congfigurable
	monitorSocket, err := net.ResolveUnixAddr("unixgram", config.MonitorSocket)
	if err != nil {
		os.Exit(1)
	}

	os.Remove(config.MonitorSocket)
	usock, err := net.ListenUnixgram("unixgram", monitorSocket)
	if err != nil {
		fmt.Printf("Error binding to monitor socket (%s): %v\n", config.MonitorSocket, err)
		os.Exit(1)
	}

	// TODO interfaces from config
	ifs, _ := net.Interfaces()
	iffs := []*net.Interface{}
	for i, _ := range ifs {
		iffs = append(iffs, &ifs[i])
	}
	interfaces = iffs

	// used for looking up reply path interface
	pm, err := initNewPathManager(iffs, &Destination{
		hostAddr: localAddress,
	}, src)
	if err != nil {
		fmt.Printf("Error initialising path manager: %v\n", err)
		os.Exit(1)
	}

	// Start HTTP API
	http.HandleFunc("/submit", http_submit)
	http.HandleFunc("/status", http_status)
	go http.ListenAndServe(":8000", nil)

	// TODO remove finished sessions after a while
	// Communication is always initiated by the server,
	// the monitor's job is to respond to queries from the server
	for {
		buf := make([]byte, C.SOCKMSG_SIZE)
		fmt.Println("read...", C.SOCKMSG_SIZE)
		n, a, err := usock.ReadFromUnix(buf)
		if err != nil {
			fmt.Println("Error reading from socket!", err)
		}
		if n > 0 {
			msgtype := binary.LittleEndian.Uint16(buf[:2])
			buf = buf[2:]
			switch msgtype {
			case C.SOCKMSG_TYPE_GET_REPLY_PATH:
				sample_len := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
				etherlen := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
				replyPath, nextHop, err := getReplyPathHeader(buf[:sample_len], int(etherlen))
				fmt.Println(err) // TODO signal error to server?
				iface, _ := pm.interfaceForRoute(nextHop)
				b := SerializePath(replyPath, iface.Index, C.HERCULES_MAX_HEADERLEN)
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
					_, _ = headersToDestination(*selectedJob) // look up paths to fix mtu
					// TODO Conversion between go and C strings?
					strlen := len(selectedJob.file)
					b = append(b, 1)
					b = binary.LittleEndian.AppendUint16(b, uint16(selectedJob.id))
					b = binary.LittleEndian.AppendUint16(b, uint16(1200))
					b = binary.LittleEndian.AppendUint16(b, uint16(strlen))
					b = append(b, []byte(selectedJob.file)...)
				} else {
					// no new jobs
					b = append(b, 0)
				}
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_GET_PATHS:
				job_id := binary.LittleEndian.Uint16(buf[:2])
				buf = buf[2:]
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
				if job.state == C.SESSION_STATE_DONE {
					job.status = Done
				}
				job.chunks_acked = int(bytes_acked) // FIXME
				job.time_elapsed = int(seconds)
				transfersLock.Unlock()
				b := binary.LittleEndian.AppendUint16(nil, uint16(1))
				usock.WriteToUnix(b, a)

			default:
				fmt.Println("Received unknown message?")
			}
		}
	}
}
