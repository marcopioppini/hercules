// Copyright 2024 ETH Zurich
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

// #include "../monitor.h"
import "C"
import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/scionproto/scion/pkg/snet"
)

var startupVersion string

type apiStatus struct {
	status      int
	state       int
	error       int
	sec_elapsed int
	bytes_acked int
}

func main() {
	flag.Usage = func() {
		fmt.Printf("This is hcp %s\nUsage: %s [OPTION]... SOURCE-API SOURCE-PATH DEST-ADDR DEST-PATH\n", startupVersion, os.Args[0])
		flag.PrintDefaults()
	}
	poll_interval := flag.Duration("i", time.Second*1, "Poll frequency")
	no_stat_file := flag.Bool("n", false, "Don't stat source file")
	show_version := flag.Bool("version", false, "Print version and exit")
	payload_len := flag.Int("l", 0, "Manually set payload length")

	flag.Parse()

	if *show_version {
		fmt.Printf("This is hcp %s\n", startupVersion)
		os.Exit(0)
	}

	if flag.NArg() != 4 {
		flag.Usage()
		os.Exit(1)
	}
	src_api := flag.Arg(0)
	src_path := flag.Arg(1)
	dst_addr := flag.Arg(2)
	dst_path := flag.Arg(3)

	// Try to parse to catch errors
	dst_parsed, err := snet.ParseUDPAddr(dst_addr)
	if err != nil {
		fmt.Println("Invalid destination address.", err)
		os.Exit(2)
	}

	if dst_parsed.Host.Port == 0 {
		fmt.Println("Destination port not set!");
		os.Exit(2)
	}

	filesize := -1
	if !*no_stat_file {
		filesize, err = stat(src_api, src_path)
		if err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
	}

	cancelChan := make(chan os.Signal, 1)
	signal.Notify(cancelChan, os.Kill)
	signal.Notify(cancelChan, os.Interrupt)

	job_id, err := submit(src_api, src_path, dst_addr, dst_path, *payload_len)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	finished := false
	old_status := apiStatus{}

	bar := progressbar.NewOptions(filesize,
		progressbar.OptionFullWidth(),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("Transfer submitted"),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowElapsedTimeOnFinish(),
	)

	for !finished {
		time.Sleep(*poll_interval)

		select {
		case <-cancelChan:
			fmt.Println("Cancelling transfer, C-c again to quit without waiting")
			cancel(src_api, job_id)
			bar.Describe("Waiting for server to confirm cancellation")
			signal.Reset()
		default:
		}

		info, err := poll(src_api, job_id)
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}

		tdiff := info.sec_elapsed - old_status.sec_elapsed
		bar.Add64(0)
		byte_diff := info.bytes_acked - old_status.bytes_acked
		if tdiff > 0 {
			// current_rate := float64(info.bytes_acked-old_status.bytes_acked) * 8 / float64(tdiff) / 1000000
			// avg_rate := 0.0
			// if info.sec_elapsed > 0 {
			// 	avg_rate = float64(info.bytes_acked) * 8 / float64(info.sec_elapsed) / 1000000
			// }
			// fmt.Printf("%.2f Mb/s, %.2f Mbps avg, %v MB transferred, %v seconds elapsed\n", current_rate, avg_rate, info.bytes_acked/1000000, info.sec_elapsed)
			bar.Describe("Transfer in progress")
			bar.Add(byte_diff)
			old_status = info
		}

		if info.state == C.SESSION_STATE_DONE {
			finished = true
			if info.error == C.SESSION_ERROR_OK {
				bar.Finish()
			}
			bar.Exit()
			fmt.Println()
			if info.error != C.SESSION_ERROR_OK {
				fmt.Println("Transfer terminated with error:", hercules_strerror(info.error))
				os.Exit(10)
			}
		}
	}

}

func submit(src_api, src_path, dst_addr, dst_path string, payload_len int) (int, error) {
	submit_url := fmt.Sprintf("http://%s/submit?file=%s&dest=%s&destfile=%s", src_api, src_path, dst_addr, dst_path)
	if payload_len != 0 {
		submit_url += fmt.Sprintf("&payloadlen=%d", payload_len)
	}
	submit_response, err := http.Get(submit_url)
	if err != nil {
		return 0, err
	}
	if submit_response.StatusCode != http.StatusOK {
		return 0, errors.New(fmt.Sprintln("HTTP status:", submit_response.StatusCode))
	}
	response_bytes, err := io.ReadAll(submit_response.Body)
	if err != nil {
		return 0, err
	}
	var job_id int
	n, err := fmt.Sscanf(string(response_bytes), "OK %d", &job_id)
	if err != nil || n != 1 {
		return 0, errors.New(fmt.Sprintln("Error parsing response", err))
	}
	return job_id, nil
}

func poll(src_api string, job_id int) (apiStatus, error) {
	var info apiStatus
	poll_url := fmt.Sprintf("http://%s/status?id=%d", src_api, job_id)
	poll_response, err := http.Get(poll_url)
	if err != nil {
		return info, err
	}
	if poll_response.StatusCode != http.StatusOK {
		return info, errors.New(fmt.Sprintln("HTTP status:", poll_response.StatusCode))
	}
	response_bytes, err := io.ReadAll(poll_response.Body)
	if err != nil {
		return info, err
	}
	// Format of the response: OK status state err seconds_elapsed bytes_acked
	n, err := fmt.Sscanf(string(response_bytes), "OK %d %d %d %d %d", &info.status, &info.state, &info.error, &info.sec_elapsed, &info.bytes_acked)
	if err != nil || n != 5 {
		return info, errors.New(fmt.Sprintln("Error parsing response", err))
	}
	return info, nil
}

func cancel(src_api string, job_id int) error {
	cancel_url := fmt.Sprintf("http://%s/cancel?id=%d", src_api, job_id)
	cancel_response, err := http.Get(cancel_url)
	if err != nil {
		return err
	}
	if cancel_response.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("HTTP status:", cancel_response.StatusCode))
	}
	return nil
}

func stat(src_api, src_path string) (int, error) {
	stat_url := fmt.Sprintf("http://%s/stat?file=%s", src_api, src_path)
	stat_response, err := http.Get(stat_url)
	if err != nil {
		return 0, err
	}
	if stat_response.StatusCode != http.StatusOK {
		return 0, errors.New(fmt.Sprintf("HTTP status:", stat_response.StatusCode))
	}
	response_bytes, err := io.ReadAll(stat_response.Body)
	if err != nil {
		return 0, err
	}
	// Response format: OK file_exists? size
	var exists int
	var size int
	n, err := fmt.Sscanf(string(response_bytes), "OK %d %d", &exists, &size)
	if err != nil || n != 2 {
		return 0, errors.New(fmt.Sprintln("Error parsing response", err))
	}
	if exists != 1 {
		return 0, errors.New("Source file does not exist?")
	}
	return size, nil
}

func hercules_strerror(errno int) string {
	switch errno {
	case C.SESSION_ERROR_NONE:
		return "Error not set"
	case C.SESSION_ERROR_OK:
		return "Transfer successful"
	case C.SESSION_ERROR_TIMEOUT:
		return "Session timed out"
	case C.SESSION_ERROR_STALE:
		return "Session stalled"
	case C.SESSION_ERROR_PCC:
		return "PCC error"
	case C.SESSION_ERROR_SEQNO_OVERFLOW:
		return "PCC sequence number overflow"
	case C.SESSION_ERROR_NO_PATHS:
		return "No paths to destination"
	case C.SESSION_ERROR_CANCELLED:
		return "Transfer cancelled"
	case C.SESSION_ERROR_BAD_MTU:
		return "Bad MTU"
	case C.SESSION_ERROR_MAP_FAILED:
		return "Mapping file failed"
	case C.SESSION_ERROR_TOO_LARGE:
		return "File or directory listing too large"
	case C.SESSION_ERROR_INIT:
		return "Could not initialise session"
	default:
		return "Unknown error"
	}
}
