package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// #include "../monitor.h"
import "C"

const HerculesMaxPktsize = C.HERCULES_MAX_PKTSIZE
const defaultConfigPath = C.HERCULES_DEFAULT_CONFIG_PATH
const defaultMonitorSocket = C.HERCULES_DEFAULT_MONITOR_SOCKET

// Select paths and serialize headers for a given transfer
func headersToDestination(transfer HerculesTransfer) (int, []byte) {
	srcA := addr.Addr{
		IA:   listenAddress.IA,
		Host: addr.MustParseHost(listenAddress.Host.IP.String()),
	}
	dstA := addr.Addr{
		IA:   transfer.dest.IA,
		Host: addr.MustParseHost(transfer.dest.Host.IP.String()),
	}
	ok := transfer.pm.choosePaths()
	if !ok {
		fmt.Println("Error choosing paths!")
		return 0, nil
	}
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
		preparedHeader, err := prepareHeader(p, transfer.pm.payloadLen, *transfer.pm.src.Host, *transfer.dest.Host, srcA, dstA)
		if err != nil {
			fmt.Println("Error preparing header!", err)
			numSelectedPaths--
			continue
		}
		serializedHeader := SerializePathHeader(&preparedHeader, p.iface.Index, C.HERCULES_MAX_HEADERLEN)
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
	Cancelled                       // The monitor has received a cancellation request
	Done                            // The server is done with the transfer (not necessarily successfully)
)

// Note that the monitor's transfer status is distinct from the server's session state.
// The monitor's status is used to distinguish queued jobs from ones already submitted to the server,
// since the server has no concept of pending jobs.

type HerculesTransfer struct {
	id           int            // ID identifying this transfer
	status       TransferStatus // Status as seen by the monitor
	file         string         // Name of the file to transfer on the source host
	destFile     string         // Name of the file to transfer at destination host
	dest         snet.UDPAddr   // Destination
	pm           *PathManager
	owner        string // The name in the certificate of whoever submitted the transfer
	timeFinished time.Time
	// The following two fields are meaningless if the job's status is 'Queued'
	// They are updated when the server sends messages of type 'update_job'
	state        C.enum_session_state // The state returned by the server
	err          C.enum_session_error // The error returned by the server
	time_elapsed int                  // Seconds the transfer has been running
	bytes_acked  int                  // Number of successfully transferred chunks
}

var transfersLock sync.Mutex // To protect the map below
var transfers = map[int]*HerculesTransfer{}
var nextID int = 1 // ID to use for the next transfer

// These are needed by the HTTP handlers
var listenAddress *snet.UDPAddr
var activeInterfaces []*net.Interface
var pathRules PathRules
var config MonitorConfig

var startupVersion string

func main() {
	fmt.Printf("Starting Hercules monitor [%v]\n", startupVersion)
	var configFile string
	flag.StringVar(&configFile, "c", defaultConfigPath, "Path to the monitor configuration file")
	flag.Parse()

	config, pathRules = readConfig(configFile)

	listenAddress = config.ListenAddress.addr

	GlobalQuerier = newPathQuerier() // XXX Can the connection time out or break?

	monitorSocket, err := net.ResolveUnixAddr("unixgram", config.MonitorSocket)
	if err != nil {
		fmt.Printf("Error resolving socket address: %s\n", config.MonitorSocket)
		os.Exit(1)
	}

	os.Remove(config.MonitorSocket)
	usock, err := net.ListenUnixgram("unixgram", monitorSocket)
	if err != nil {
		fmt.Printf("Error binding to monitor socket (%s): %v\n", config.MonitorSocket, err)
		os.Exit(1)
	}

	activeInterfaces = []*net.Interface{}
	for _, i := range config.Interfaces {
		activeInterfaces = append(activeInterfaces, i.iface)
	}

	// used for looking up reply path interface
	pm, err := initNewPathManager(activeInterfaces, &Destination{
		hostAddr: config.ListenAddress.addr,
	}, config.ListenAddress.addr, 0)
	if err != nil {
		fmt.Printf("Error initialising path manager: %v\n", err)
		os.Exit(1)
	}

	// Start HTTP API
	http.HandleFunc("/submit", http_submit)
	http.HandleFunc("/status", http_status)
	http.HandleFunc("/cancel", http_cancel)
	http.HandleFunc("/stat", http_stat)
	if config.MonitorHTTP != "disabled" {
		go http.ListenAndServe(config.MonitorHTTP, nil)
	}

	if config.MonitorHTTPS != "disabled" {
		clientCAs := x509.NewCertPool()
		for _, c := range config.ClientCACerts {
			cert, err := os.ReadFile(c)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				os.Exit(1)
			}
			clientCAs.AppendCertsFromPEM(cert)
		}
		httpsServer := &http.Server{
			Addr: config.MonitorHTTPS,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  clientCAs,
			},
		}
		go httpsServer.ListenAndServeTLS(config.TLSCert, config.TLSKey)
	}

	// Communication is always initiated by the server,
	// the monitor's job is to respond to queries from the server
	for {
		buf := make([]byte, C.SOCKMSG_SIZE)
		n, a, err := usock.ReadFromUnix(buf)
		if err != nil {
			fmt.Println("Error reading from socket!", err)
			os.Exit(1)
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
				var b []byte
				if err != nil {
					fmt.Println("Error in reply path lookup:", err)
					b = append(b, 0)
					usock.WriteToUnix(b, a)
					continue
				}
				iface, err := pm.interfaceForRoute(nextHop)
				if err != nil {
					fmt.Println("Error in reply interface lookup:", err)
					b = append(b, 0)
					usock.WriteToUnix(b, a)
					continue
				}
				b = append(b, 1)
				b = append(b, SerializePathHeader(replyPath, iface.Index, C.HERCULES_MAX_HEADERLEN)...)
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_GET_NEW_JOB:
				transfersLock.Lock()
				var selectedJob *HerculesTransfer = nil
				for k, job := range transfers {
					if job.status == Done && time.Since(job.timeFinished) > time.Hour {
						// Clean up old jobs while we're at it
						delete(transfers, k)
					}
					if job.status == Queued {
						selectedJob = job
						job.status = Submitted
						break
					}
				}
				transfersLock.Unlock()
				var b []byte
				if selectedJob != nil {
					fmt.Println("Sending transfer to daemon:", selectedJob.file, selectedJob.destFile, selectedJob.id)
					_, _ = headersToDestination(*selectedJob) // look up paths to fix mtu
					strlen_src := len(selectedJob.file)
					strlen_dst := len(selectedJob.destFile)
					b = append(b, 1)
					b = binary.LittleEndian.AppendUint64(b, uint64(selectedJob.id))

					// Address components in network byte order
					b = binary.BigEndian.AppendUint64(b, uint64(selectedJob.dest.IA))
					b = append(b, selectedJob.dest.Host.IP[len(selectedJob.dest.Host.IP)-4:]...)
					b = binary.BigEndian.AppendUint16(b, uint16(selectedJob.dest.Host.Port))

					b = binary.LittleEndian.AppendUint16(b, uint16(selectedJob.pm.payloadLen))
					b = binary.LittleEndian.AppendUint16(b, uint16(strlen_src))
					b = binary.LittleEndian.AppendUint16(b, uint16(strlen_dst))
					b = append(b, []byte(selectedJob.file)...)
					b = append(b, []byte(selectedJob.destFile)...)
				} else {
					// no new jobs
					b = append(b, 0)
				}
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_GET_PATHS:
				job_id := binary.LittleEndian.Uint64(buf[:8])
				buf = buf[8:]
				transfersLock.Lock()
				job, _ := transfers[int(job_id)]
				n_headers, headers := headersToDestination(*job)
				transfersLock.Unlock()
				b := binary.LittleEndian.AppendUint16(nil, uint16(n_headers))
				b = append(b, headers...)
				usock.WriteToUnix(b, a)

			case C.SOCKMSG_TYPE_UPDATE_JOB:
				job_id := binary.LittleEndian.Uint64(buf[:8])
				buf = buf[8:]
				status := binary.LittleEndian.Uint32(buf[:4])
				buf = buf[4:]
				errorcode := binary.LittleEndian.Uint32(buf[:4])
				buf = buf[4:]
				seconds := binary.LittleEndian.Uint64(buf[:8])
				buf = buf[8:]
				bytes_acked := binary.LittleEndian.Uint64(buf[:8])
				buf = buf[8:]
				fmt.Println("updating job", job_id, status, errorcode)
				var b []byte
				transfersLock.Lock()
				job, ok := transfers[int(job_id)]
				if !ok {
					b = binary.LittleEndian.AppendUint16(b, uint16(0))
					usock.WriteToUnix(b, a)
					continue
				}
				job.state = status
				job.err = errorcode
				if job.state == C.SESSION_STATE_DONE {
					job.status = Done
					job.timeFinished = time.Now()
				}
				job.bytes_acked = int(bytes_acked)
				job.time_elapsed = int(seconds)
				isCancelled := job.status == Cancelled
				transfersLock.Unlock()
				if isCancelled {
					b = binary.LittleEndian.AppendUint16(b, uint16(0))
				} else {
					b = binary.LittleEndian.AppendUint16(b, uint16(1))
				}
				usock.WriteToUnix(b, a)

			default:
				fmt.Println("Received unknown message?")
			}
		}
	}
}
