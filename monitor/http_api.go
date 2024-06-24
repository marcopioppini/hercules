package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/scionproto/scion/pkg/snet"
)

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
	info.status = Cancelled
	transfersLock.Unlock()

	io.WriteString(w, "OK\n")
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
	info, err := os.Stat(file)
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
		io.WriteString(w, "err\n")
		return
	}

	io.WriteString(w, fmt.Sprintf("OK 1 %d\n", info.Size()))
}
