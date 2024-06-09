package main

import (
	"fmt"
	"io"
	"net/http"
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
