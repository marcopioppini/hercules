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

#ifndef GFAL_HERCULES_TRANSFER_H_
#define GFAL_HERCULES_TRANSFER_H_

#include <glib.h>
#include <gfal2/gfal_api.h>
#include <gfal2/gfal_plugins_api.h>

int gfal_plugin_hercules_copy_file(plugin_handle h, gfal2_context_t ctxt,
                                   gfalt_params_t params, const char *src,
                                   const char *dst, GError **err);

int gfal_plugin_hercules_statG(plugin_handle h, const char *name,
                               struct stat *buf, GError **err);

#endif // GFAL_HERCULES_TRANSFER_H_
