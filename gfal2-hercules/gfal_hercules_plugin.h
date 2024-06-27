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
