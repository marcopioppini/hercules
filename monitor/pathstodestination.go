// Copyright 2019 ETH Zurich
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

import (
	"context"
	"fmt"
	log "github.com/inconshreveable/log15"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology"
	"go.uber.org/atomic"
	"net"
	"time"
)

var GlobalQuerier snet.PathQuerier

type PathsToDestination struct {
	pm             *PathManager
	dst            *Destination
	modifyTime     time.Time
	ExtnUpdated    atomic.Bool
	allPaths       []snet.Path
	paths          []PathMeta // nil indicates that the destination is in the same AS as the sender and we can use an empty path
	canSendLocally bool // (only if destination in same AS) indicates if we can send packets
}

type PathMeta struct {
	path        snet.Path
	fingerprint snet.PathFingerprint
	iface       *net.Interface
	enabled     bool // Indicates whether this path can be used at the moment
	updated     bool // Indicates whether this path needs to be synced to the C path
}

type HerculesPathHeader struct {
	Header          []byte //!< C.HERCULES_MAX_HEADERLEN bytes
	PartialChecksum uint16 //SCION L4 checksum over header with 0 payload
}

func initNewPathsToDestinationWithEmptyPath(pm *PathManager, dst *Destination) *PathsToDestination {
	return &PathsToDestination{
		pm:         pm,
		dst:        dst,
		paths:      nil,
		modifyTime: time.Now(),
	}
}

func initNewPathsToDestination(pm *PathManager, src *snet.UDPAddr, dst *Destination) (*PathsToDestination, error) {
	return &PathsToDestination{
		pm:         pm,
		dst:        dst,
		allPaths:   nil,
		paths:      make([]PathMeta, dst.numPaths),
		modifyTime: time.Unix(0, 0),
	}, nil
}

func (ptd *PathsToDestination) hasUsablePaths() bool {
	if ptd.paths == nil {
		return ptd.canSendLocally
	}
	for _, path := range ptd.paths {
		if path.enabled {
			return true
		}
	}
	return false
}

func (ptd *PathsToDestination) choosePaths() bool {
	var err error
	ptd.allPaths, err = GlobalQuerier.Query(context.Background(), ptd.dst.hostAddr.IA)
	if err != nil {
		return false
	}

	if ptd.allPaths == nil {
		return false
	}

	fmt.Println("all paths", ptd.allPaths)
	availablePaths := ptd.pm.filterPathsByActiveInterfaces(ptd.allPaths)
	if len(availablePaths) == 0 {
		log.Error(fmt.Sprintf("no paths to destination %s", ptd.dst.hostAddr.IA.String()))
	}

	// TODO Ensure this still does the right thing when the number of paths decreases (how to test?)
	ptd.chooseNewPaths(&availablePaths)

	fmt.Println("chosen paths", ptd.paths)
	return true
}

func (ptd *PathsToDestination) choosePreviousPaths(previousPathAvailable *[]bool, availablePaths *AppPathSet) bool {
	updated := false
	for newFingerprint := range *availablePaths {
		for i := range ptd.paths {
			pathMeta := &ptd.paths[i]
			if newFingerprint == pathMeta.fingerprint {
				if !pathMeta.enabled {
					log.Info(fmt.Sprintf("[Destination %s] re-enabling path %d\n", ptd.dst.hostAddr.IA, i))
					pathMeta.enabled = true
					updated = true
				}
				(*previousPathAvailable)[i] = true
				break
			}
		}
	}
	return updated
}

func (ptd *PathsToDestination) disableVanishedPaths(previousPathAvailable *[]bool) bool {
	updated := false
	for i, inUse := range *previousPathAvailable {
		pathMeta := &ptd.paths[i]
		if inUse == false && pathMeta.enabled {
			log.Info(fmt.Sprintf("[Destination %s] disabling path %d\n", ptd.dst.hostAddr.IA, i))
			pathMeta.enabled = false
			updated = true
		}
	}
	return updated
}

func (ptd *PathsToDestination) chooseNewPaths(availablePaths *AppPathSet) bool {
	updated := false

	// pick paths
	picker := makePathPicker(ptd.dst.pathSpec, availablePaths, ptd.dst.numPaths)
	var pathSet []snet.Path
	disjointness := 0 // negative number denoting how many network interfaces are shared among paths (to be maximized)
	maxRuleIdx := 0   // the highest index of a PathSpec that is used (to be minimized)
	for i := ptd.dst.numPaths; i > 0; i-- {
		picker.reset(i)
		for picker.nextRuleSet() { // iterate through different choices of PathSpecs to use
			if pathSet != nil && maxRuleIdx < picker.maxRuleIdx() { // ignore rule set, if path set with lower maxRuleIndex is known
				continue // due to the iteration order, we cannot break here
			}
			for picker.nextPick() { // iterate through different choices of paths obeying the rules of the current set of PathSpecs
				curDisjointness := picker.disjointnessScore()
				if pathSet == nil || disjointness < curDisjointness { // maximize disjointness
					disjointness = curDisjointness
					maxRuleIdx = picker.maxRuleIdx()
					pathSet = picker.getPaths()
				}
			}
		}
		if pathSet != nil { // if no path set of size i found, try with i-1
			break
		}
	}

	log.Info(fmt.Sprintf("[Destination %s] using %d paths:", ptd.dst.hostAddr.IA, len(pathSet)))
	for i, path := range pathSet {
		log.Info(fmt.Sprintf("\t%s", path))
		fingerprint := snet.Fingerprint(path)
		ptd.paths[i].path = path
		ptd.paths[i].fingerprint = fingerprint
		ptd.paths[i].enabled = true
		ptd.paths[i].updated = true
		ptd.paths[i].iface = (*availablePaths)[fingerprint].iface
		updated = true
	}
	return updated
}

func (ptd *PathsToDestination) preparePath(p *PathMeta) (*HerculesPathHeader, error) {
	var err error
	var iface *net.Interface
	curDst := ptd.dst.hostAddr
	fmt.Println("preparepath", curDst, iface)
	if (*p).path == nil {
		// in order to use a static empty path, we need to set the next hop on dst
		fmt.Println("empty path")
		curDst.NextHop = &net.UDPAddr{
			IP:   ptd.dst.hostAddr.Host.IP,
			Port: topology.EndhostPort,
		}
		fmt.Println("nexthop", curDst.NextHop)
		iface, err = ptd.pm.interfaceForRoute(ptd.dst.hostAddr.Host.IP)
		if err != nil {
			return nil, err
		}
		curDst.Path = path.Empty{}
	} else {
		curDst.Path = (*p).path.Dataplane()

		curDst.NextHop = (*p).path.UnderlayNextHop()
		iface = p.iface
	}

	// path, err := prepareSCIONPacketHeader(ptd.pm.src, curDst, iface)
	// if err != nil {
	// 	return nil, err
	// }
	// return path, nil
	return nil, fmt.Errorf("NOPE")
}
