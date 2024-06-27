#include "gfal_hercules_plugin.h"
#include "gfal_hercules_transfer.h"
#include <asm-generic/errno-base.h>
#include <curl/curl.h>
#include <gfal2/gfal_api.h>
#include <gfal2/gfal_plugins_api.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// The documentation for how to write gfal plugins is somewhat sparse,
// this has been pieced together by looking at the code of existing plugins;
// Note also the dropbox gfal plugin (not included in the gfal2 repository, but
// at github.com/cern-fts/gfal2-dropbox), which also uses libcurl to talk to a
// HTTP API.

GQuark hercules_domain() { return g_quark_from_static_string("hercules"); }

// Return the plugin name and version
// (I believe newer versions will take precedence, if multiple are installed)
const char *gfal_hercules_plugin_get_name() {
  return GFAL2_PLUGIN_VERSIONED("hercules", "0.1");
}

static gboolean is_hercules_url(const char *url) {
  return strncmp(url, "hercules:", 9) == 0;
}

// This is called by gfal to check whether our plugin supports a given operation
// on a URL.
static gboolean gfal_hercules_check_url(plugin_handle h, const char *url,
                                        plugin_mode mode, GError **err) {
  (void)h;
  (void)err;
  switch (mode) {
    // We don't support any file operations.
    // STAT is required as it's called before any transfer
  case GFAL_PLUGIN_STAT:
    return is_hercules_url(url);
  default:
    return FALSE;
  }
}

// Delete plugin data, called by gfal for cleanup
static void gfal_plugin_hercules_delete(plugin_handle plugin_data) {
  struct gfal_hercules_context *data =
      (struct gfal_hercules_context *)plugin_data;
  curl_easy_cleanup(data->curl);
  free(data->user_key);
  free(data->user_cert);
  free(data);
}

// This will be called to determine whether the hercules plugin can handle
// a transfer of src to dst.
int gfal_plugin_hercules_check_url_transfer(plugin_handle h,
                                            gfal2_context_t ctxt,
                                            const char *src, const char *dst,
                                            gfal_url2_check check) {
  (void)h;
  (void)ctxt;
  // XXX I'm not sure what the `check` arg is used for
  return is_hercules_url(src) && is_hercules_url(dst);
}

// This is used by gfal to register the plugin
gfal_plugin_interface gfal_plugin_init(gfal2_context_t context, GError **err) {
  // Interface struct, create and zero out (to set all function pointers to
  // NULL)
  gfal_plugin_interface hercules_plugin;
  memset(&hercules_plugin, 0, sizeof(gfal_plugin_interface));

  GError *tmp_err = NULL;

  // Context we can fill with whatever we want,
  // will be passed to function calls
  struct gfal_hercules_context *data = calloc(1, sizeof(*data));
  if (data == NULL) {
    gfal2_set_error(&tmp_err, hercules_domain(), ENOMEM, __func__,
                    "calloc failed");
    // Error is returned at the end
  }
  data->gfal2_context = context;
  data->curl = curl_easy_init();
  if (data->curl == NULL) {
    gfal2_set_error(&tmp_err, hercules_domain(), EINVAL, __func__,
                    "CURL init error");
    // Error is returned at the end
  }

  // Now fill in the struct
  // MANDATORY fields
  hercules_plugin.plugin_data = data;
  hercules_plugin.priority = GFAL_PLUGIN_PRIORITY_DATA;
  hercules_plugin.getName = gfal_hercules_plugin_get_name;
  hercules_plugin.plugin_delete = gfal_plugin_hercules_delete;
  hercules_plugin.check_plugin_url = gfal_hercules_check_url;

  // FILE API
  // Not supported, but stat is required
  hercules_plugin.statG = gfal_plugin_hercules_statG;

  // TRANSFER API
  //   return whether we support third-party transfer from src to dst
  hercules_plugin.check_plugin_url_transfer =
      gfal_plugin_hercules_check_url_transfer;
  //   perform file copy
  hercules_plugin.copy_file = gfal_plugin_hercules_copy_file;
  //   Not clear to me what bulk copy is. I think it refers to the ability to
  //   submit a batch of transfers to FTS in a single submission. I'm not
  //   sure why we'd need to handle that differently, it may just be an
  //   optimisation?
  hercules_plugin.copy_bulk = NULL;
  //   hook executed before a copy, may be useful?
  hercules_plugin.copy_enter_hook = NULL;

  // QoS API
  // Not supported

  // ARCHIVE API
  // Not supported

  // TOKEN API
  // Not supported

  // Returning an error here seems to leave the transfer hanging around as
  // "active" in the FTS dashboard. It will only be marked as failed after 900
  // seconds, which means that no error is reported for that time. The gridftp
  // plugin does the same, though.
  G_RETURN_ERR(hercules_plugin, tmp_err, err);
}
