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

#ifndef GFAL_HERCULES_PLUGIN_H
#define GFAL_HERCULES_PLUGIN_H

#include <gfal2/gfal_api.h>
#include <gfal2/gfal_plugins_api.h>
#include <curl/curl.h>
#include <glib.h>

// This can be used to keep state between function calls, gfal passes it into
// every call. (1 per transfer)
struct gfal_hercules_context {
  CURL *curl;
  gfal2_context_t gfal2_context;
  gchar *user_cert;
  gchar *user_key;
};

GQuark hercules_domain();

#endif // GFAL_HERCULES_PLUGIN_H
