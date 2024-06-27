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
