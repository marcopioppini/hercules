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
// file (File to transfer)
// dest (Destination IA+Host)
func http_submit(w http.ResponseWriter, r *http.Request) {
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
	destination := findPathRule(&pathRules, destParsed)
	pm, _ := initNewPathManager(interfaces, &destination, localAddress)

	transfersLock.Lock()
	jobid := nextID
	transfers[nextID] = &HerculesTransfer{
		id:     nextID,
		status: Queued,
		file:   file,
		dest:   *destParsed,
		pm:     pm,
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

// Handle cancelling a transfer
// GET Params:
// id: An ID obtained by submitting a transfer
// Returns OK
func http_cancel(w http.ResponseWriter, r *http.Request) {
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
	if !ok {
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
		io.WriteString(w, "missing parameter")
		return
	}
	file := r.URL.Query().Get("file")
	info, err := os.Stat(file)
	if os.IsNotExist(err){
		io.WriteString(w, "OK 0 0\n");
		return
	} else if err != nil {
		io.WriteString(w, "err\n")
		return
	}
	if !info.Mode().IsRegular() {
		io.WriteString(w, "err\n")
		return
	}

	io.WriteString(w, fmt.Sprintf("OK 1 %d\n", info.Size()))
}
