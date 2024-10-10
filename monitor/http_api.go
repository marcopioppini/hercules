package main

import (
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/scionproto/scion/pkg/snet"
)

// Check if the user can open the file
func checkReadPerm(user, file string) bool {
	ug, ok := config.UserMap[user]
	if !ok {
		return false
	}

	err := syscall.Setegid(ug.gidLookup)
	if err != nil {
		return false
	}
	defer syscall.Setegid(0)
	err = syscall.Seteuid(ug.uidLookup)
	if err != nil {
		return false
	}
	defer syscall.Seteuid(0)

	f, err := os.Open(file)
	if err != nil {
		return false
	}
	err = f.Close()
	if err != nil {
		return false
	}
	return true
}

// Handle submission of a new transfer
// GET params:
// file (Path to file to transfer)
// destfile (Path at destination)
// dest (Destination IA+Host)
// payloadlen (optional, override automatic MTU selection)
func http_submit(w http.ResponseWriter, r *http.Request) {
	if !r.URL.Query().Has("file") || !r.URL.Query().Has("destfile") || !r.URL.Query().Has("dest") {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "Missing parameter\n")
		return
	}
	file := r.URL.Query().Get("file")
	destfile := r.URL.Query().Get("destfile")
	dest := r.URL.Query().Get("dest")
	destParsed, err := snet.ParseUDPAddr(dest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "parse err\n")
		return
	}
	owner := ""
	if r.TLS != nil {
		// There must be at least 1 cert because we require client certs in the TLS config
		certDN := r.TLS.PeerCertificates[0].Subject.String()
		fmt.Println("Read user from cert:", certDN)
		if !checkReadPerm(certDN, file) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "Source file does not exist or insufficient permissions\n")
			return
		}
		owner = certDN
	}

	payloadlen := 0 // 0 means automatic selection
	if r.URL.Query().Has("payloadlen") {
		payloadlen, err = strconv.Atoi(r.URL.Query().Get("payloadlen"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "parse err\n")
			return
		}
	}

	destination := findPathRule(&pathRules, destParsed)

	// If the config specifies a payload length, use that value
	if destination.payloadlen != 0 {
		payloadlen = destination.payloadlen
	}

	pm, err := initNewPathManager(activeInterfaces, &destination, listenAddress, payloadlen)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Printf("Received submission: %v -> %v %v\n", file, dest, destfile)
	transfersLock.Lock()
	jobid := nextID
	transfers[nextID] = &HerculesTransfer{
		id:       nextID,
		status:   Queued,
		file:     file,
		destFile: destfile,
		dest:     *destParsed,
		owner:    owner,
		pm:       pm,
	}
	nextID += 1
	transfersLock.Unlock()

	io.WriteString(w, fmt.Sprintf("OK %d\n", jobid))
}

// Handle querying a transfer's status
// GET Params:
// id: An ID obtained by submitting a transfer
// Returns OK status state err seconds_elapsed chucks_acked
func http_status(w http.ResponseWriter, r *http.Request) {
	if !r.URL.Query().Has("id") {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "missing parameter\n")
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	transfersLock.Lock()
	info, ok := transfers[id]
	transfersLock.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.TLS != nil {
		if info.owner != r.TLS.PeerCertificates[0].Subject.String() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	io.WriteString(w, fmt.Sprintf("OK %d %d %d %d %d\n", info.status, info.state, info.err, info.time_elapsed, info.bytes_acked))
}

// Handle cancelling a transfer
// GET Params:
// id: An ID obtained by submitting a transfer
// Returns OK
func http_cancel(w http.ResponseWriter, r *http.Request) {
	if !r.URL.Query().Has("id") {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "missing parameter\n")
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	transfersLock.Lock()
	info, ok := transfers[id]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		transfersLock.Unlock()
		return
	}
	if r.TLS != nil {
		if info.owner != r.TLS.PeerCertificates[0].Subject.String() {
			w.WriteHeader(http.StatusUnauthorized)
			transfersLock.Unlock()
			return
		}
	}
	info.status = Cancelled
	transfersLock.Unlock()

	io.WriteString(w, "OK\n")
}

func statAsUser(user, file string) (fs.FileInfo, error) {
	ug, ok := config.UserMap[user]
	if !ok {
		return nil, fmt.Errorf("No user?")
	}

	err := syscall.Setegid(ug.gidLookup)
	if err != nil {
		return nil, err
	}
	defer syscall.Setegid(0)
	err = syscall.Seteuid(ug.uidLookup)
	if err != nil {
		return nil, err
	}
	defer syscall.Seteuid(0)

	return os.Stat(file)
}

// Handle gfal's stat command
// GET Params:
// file: a file path
// Returns OK exists? size
func http_stat(w http.ResponseWriter, r *http.Request) {
	if !r.URL.Query().Has("file") {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "missing parameter\n")
		return
	}
	file := r.URL.Query().Get("file")
	var info fs.FileInfo
	var err error
	if r.TLS != nil {
		// There must be at least 1 cert because we require client certs in the TLS config
		certDN := r.TLS.PeerCertificates[0].Subject.String()
		fmt.Println("Read user from cert:", certDN)
		info, err = statAsUser(certDN, file)
	} else {
		info, err = os.Stat(file)
	}
	if os.IsNotExist(err) {
		io.WriteString(w, "OK 0 0\n")
		return
	} else if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "err\n")
		return
	}
	if !info.Mode().IsRegular() && !info.Mode().IsDir() {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "File is not a regular file or directory\n")
		return
	}

	totalSize := info.Size()
	if info.Mode().IsDir() {
		dirSize := 0
		walker := func(_ string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				dirSize += int(info.Size())
			}
			return nil
		}
		err := filepath.Walk(file, walker)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		totalSize = int64(dirSize)
	}

	io.WriteString(w, fmt.Sprintf("OK 1 %d\n", totalSize))
}

// Return the server's SCION address (needed for gfal)
func http_server(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, fmt.Sprintf("OK %s", config.ListenAddress.addr.String()))
}
