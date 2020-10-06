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
	"bytes"
	"fmt"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

type PathInterface struct {
	ia   addr.IA
	ifId common.IFIDType
}

func (iface *PathInterface) ID() common.IFIDType {
	return iface.ifId
}

func (iface *PathInterface) IA() addr.IA {
	return iface.ia
}

func (iface *PathInterface) UnmarshalText(text []byte) error {
	parts := bytes.Split(text, []byte{' '})
	if len(parts) > 2 {
		return fmt.Errorf("cannot unmarshal \"%s\" as PathInterface: contains too many spaces", text)
	}
	if len(parts) > 1 {
		if err := iface.ifId.UnmarshalText(parts[1]); err != nil {
			return err
		}
	}
	ret := iface.ia.UnmarshalText(parts[0])
	return ret
}

func (iface *PathInterface) match(pathIface snet.PathInterface) bool {
	if iface.ifId == 0 {
		return iface.IA() == pathIface.IA()
	}
	return iface.ID() == pathIface.ID() && iface.IA() == pathIface.IA()
}
