#include "gfal_hercules_transfer.h"
#include "../errors.h"
#include "common/gfal_common.h"
#include "gfal_hercules_plugin.h"
#include <asm-generic/errno.h>
#include <bits/stdint-uintn.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <gfal2/gfal_api.h>
#include <gfal2/gfal_plugins_api.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// In order to get the HTTP response from libcurl, we need to supply it with a
// receive callback (a function and an argument where that function will store
// the received data). This is a very simple implementation since we expect the
// responses to be very short.
#define MAX_RESPONSE_DATA 100
struct recvdata {
  char response[MAX_RESPONSE_DATA];
  size_t size; // Actual response size
};

// Callback function to receive HTTP responses.
// Copied from libcurl docs.
static size_t recvfunc(char *data, size_t size, size_t nmemb,
                       struct recvdata *s) {
  size_t realsize = size * nmemb;
  if (s->size + realsize > MAX_RESPONSE_DATA) {
    return 0;
  }
  memcpy(&(s->response[s->size]), data, realsize);
  s->size += realsize;
  s->response[s->size] = 0;
  return realsize;
}

static int curl_get_and_check(CURL *curl, GError **err) {
  CURLcode res;
  res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__, "CURL error: %s",
                    curl_easy_strerror(res));
    return -1;
  }

  long response_code;
  res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  if (res != CURLE_OK) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__, "CURL error: %s",
                    curl_easy_strerror(res));
    return -1;
  }
  if (response_code != 200) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error (HTTP status %ld)", response_code);
    return -1;
  }
  return 0;
}

// Ask the destination monitor for its server's address
static int hercules_get_server(CURL *curl, struct recvdata *rec,
                               char *dst_host_monitor,
                               char dst_host_server[500], GError **err) {
  char server_request_url[800];
  int ret =
      snprintf(server_request_url, 800, "https://%s/server", dst_host_monitor);
  if (ret >= 800) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Server query URL too long");
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_DEBUG, "Hercules: Using URL %s", server_request_url);

  curl_easy_setopt(curl, CURLOPT_URL, server_request_url);
  rec->size = 0;
  ret = curl_get_and_check(curl, err);
  if (ret) {
    return -1;
  }

  printf("read %s\n", rec->response);
  ret = sscanf(rec->response, "OK %499s", dst_host_server);
  if (ret != 1) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error parsing HTTP response?");
    return -1;
  }
  return 0;
}

static int hercules_submit_transfer(CURL *curl, struct recvdata *rec,
                                    char *src_host, char *dst_server,
                                    char *src_path, char *dst_path,
                                    uint64_t *jobid, GError **err) {
  char request_url[3000];
  int ret = snprintf(request_url, 3000,
                     "https://%s/submit?file=%s&dest=%s&destfile=%s", src_host,
                     src_path, dst_server, dst_path);
  if (ret >= 3000) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Submission URL too long");
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_DEBUG, "Hercules: Using URL %s", request_url);

  curl_easy_setopt(curl, CURLOPT_URL, request_url);
  rec->size = 0;
  ret = curl_get_and_check(curl, err);
  if (ret) {
    return -1;
  }

  // Parse response
  ret = sscanf(rec->response, "OK %lu", jobid);
  if (ret != 1) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error parsing HTTP response?");
    return -1;
  }
  return 0;
}

struct hercules_status_info {
  int status;
  enum session_state state;
  enum session_error job_err;
  int seconds_elapsed;
  int bytes_acked;
};

// Query current transfer status
static int hercules_get_status(CURL *curl, struct recvdata *rec, char *src_host,
                               uint64_t jobid,
                               struct hercules_status_info *status,
                               GError **err) {
  char status_url[1000];
  int ret =
      snprintf(status_url, 1000, "https://%s/status?id=%lu", src_host, jobid);
  if (ret >= 1000) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Status URL too long");
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, status_url);
  rec->size = 0;
  ret = curl_get_and_check(curl, err);
  if (ret) {
    return -1;
  }

  // Format of the response: OK status state err seconds_elapsed bytes_acked
  ret = sscanf(rec->response, "OK %d %d %d %d %d", &status->status,
               (int *)&status->state, (int *)&status->job_err,
               &status->seconds_elapsed, &status->bytes_acked);
  if (ret != 5) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error parsing HTTP response?");
    return -1;
  }
  return 0;
}

static int hercules_cancel_transfer(CURL *curl, struct recvdata *rec,
                                    char *src_host, uint64_t jobid,
                                    GError **err) {
  char cancel_url[1000];
  int ret =
      snprintf(cancel_url, 1000, "https://%s/cancel?id=%lu", src_host, jobid);
  if (ret >= 1000) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Cancel URL too long");
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, cancel_url);
  rec->size = 0;
  ret = curl_get_and_check(curl, err);
  if (ret) {
    return -1;
  }

  // Format of the response: OK
  if (strncmp(rec->response, "OK", 2)) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error cancelling transfer?");
    return -1;
  }
  return 0;
}

// Will be registered as callback below
void gfal_plugin_hercules_cancel_transfer(gfal2_context_t ctxt, void *data) {
  (void)ctxt;
  int *cancel_received = (int *)data;
  *cancel_received = 1;
}

// This function will be called to perform the actual transfer.
// We submit the transfer to the hercules server at src,
// then periodically poll the transfer's status and update FTS accordingly.
//
// We expect URLs of the form:
// hercules://10.0.0.1:8000/path/to/file
// NOTE: The source and destination URLs both refer to the respective Hercules
// monitor's HTTP API. We first need to ask the receiving-side monitor for its
// SCION address (the reason is that stat is called on the destination URL
// first, so it has to refer to the monitor, not the server).
//
// To submit the transfer, send a HTTP GET request to the source host of the
// form
// http://src:api_port/?file=testfile&dest=17-ffaa:1:fe2,127.0.0.1:123&destfile=out
int gfal_plugin_hercules_copy_file(plugin_handle h, gfal2_context_t ctxt,
                                   gfalt_params_t params, const char *src,
                                   const char *dst, GError **err) {
  gfal2_log(G_LOG_LEVEL_INFO, "Hercules executing transfer: %s -> %s", src,
            dst);
  struct gfal_hercules_context *data = (struct gfal_hercules_context *)h;

  // Get client certificate to use
  // This gets us the path to the key/cert files
  GError *e = NULL;
  gchar *user_cert = gfal2_cred_get(ctxt, GFAL_CRED_X509_CERT, src, NULL, &e);
  if (e || !user_cert) {
    g_propagate_error(err, e);
    return -1;
  }
  if (data->user_cert) {
    free(data->user_cert);
    data->user_cert = NULL;
  }
  data->user_cert = user_cert;
  gfal2_log(G_LOG_LEVEL_MESSAGE, "cert: %s", user_cert);
  g_clear_error(&e);
  gchar *user_key = gfal2_cred_get(ctxt, GFAL_CRED_X509_KEY, src, NULL, &e);
  if (e || !user_key) {
    g_propagate_error(err, e);
    return -1;
  }
  if (data->user_key) {
    free(data->user_key);
    data->user_key = NULL;
  }
  data->user_key = user_key;
  g_clear_error(&e);
  gfal2_log(G_LOG_LEVEL_MESSAGE, "key: %s", user_key);

  // Parse the source URL
  char src_host[500];
  char src_path[1000];
  int ret = sscanf(src, "hercules://%499[^/]/%999s", src_host, src_path);
  if (ret != 2) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error parsing source URL");
    return -1;
  }

  // Parse the destination URL
  char dst_host_monitor[500];
  char dst_path[1000];
  ret = sscanf(dst, "hercules://%499[^/]/%999s", dst_host_monitor, dst_path);
  if (ret != 2) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error parsing destination URL");
    return -1;
  }

  // Set up curl
  CURL *curl = data->curl;
  struct recvdata rec = {.size = 0};

  /* curl_easy_setopt(curl, CURLOPT_URL, url_goes_here); */
  curl_easy_setopt(curl, CURLOPT_SSLCERT, user_cert);
  curl_easy_setopt(curl, CURLOPT_SSLKEY, user_key);
  /* curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); */
  /* curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); */
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recvfunc);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rec);

  // Get destination server address
  char dst_host_server[500];
  ret = hercules_get_server(curl, &rec, dst_host_monitor, dst_host_server, err);
  if (ret) {
    return -1;
  }

  // Submit the transfer
  uint64_t jobid;
  ret = hercules_submit_transfer(curl, &rec, src_host, dst_host_server,
                                 src_path, dst_path, &jobid, err);
  if (ret) {
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_INFO, "Hercules: Job ID: %lu", jobid);
  plugin_trigger_event(params, hercules_domain(), GFAL_EVENT_NONE,
                       GFAL_EVENT_TRANSFER_ENTER, "Hercules starting transfer");

  // Register cancel callback
  int cancel_received = 0;
  gfal_cancel_token_t cancel_token = gfal2_register_cancel_callback(
      ctxt, gfal_plugin_hercules_cancel_transfer, &cancel_received);

  // Poll the transfer's status until it's done
  // In seconds
#define HERCULES_POLL_INTERVAL 60
  int transfer_finished = 0;

  // We fill this struct with the transfer's current stats and then pass it to
  // the monitor.
  // NOTE: In this case, "monitor" refers to gfal/fts' monitor,
  // NOT the Hercules monitor.
  struct _gfalt_transfer_status stat;
  stat.status =
      0; // XXX Not clear what this does, the other plugins set it to 0
  stat.average_baudrate = 0; // This seems to be in bytes per second
  stat.instant_baudrate = 0; // Idem
  stat.bytes_transfered = 0;
  stat.transfer_time = 0;

  while (!transfer_finished) {
    sleep(HERCULES_POLL_INTERVAL);

    if (cancel_received) {
      ret = hercules_cancel_transfer(curl, &rec, src_host, jobid, err);
      if (ret) {
        return -1;
      }
      gfal2_set_error(err, hercules_domain(), ECANCELED, __func__,
                      "Transfer cancelled");
      return -1;
    }

    struct hercules_status_info status;
    ret = hercules_get_status(curl, &rec, src_host, jobid, &status, err);
    if (ret) {
      return -1;
    }

    int tdiff = status.seconds_elapsed - stat.transfer_time;
    int bdiff = status.bytes_acked - stat.bytes_transfered;
    stat.average_baudrate = (status.seconds_elapsed != 0)
                                ? status.bytes_acked / status.seconds_elapsed
                                : 0;
    stat.instant_baudrate = (tdiff != 0) ? bdiff / tdiff : 0;
    stat.bytes_transfered = status.bytes_acked;
    stat.transfer_time = status.seconds_elapsed;
    // Inform FTS about current status
    plugin_trigger_monitor(params, &stat, src, dst);

    if (status.state == SESSION_STATE_DONE) {
      transfer_finished = 1;
      if (!hercules_err_is_ok(status.job_err)) {
        gfal2_set_error(err, hercules_domain(), status.job_err, __func__,
                        "Hercules session error: %s",
                        hercules_strerror(status.job_err));
        return -1;
      }
    }
  }
  gfal2_remove_cancel_callback(ctxt, cancel_token);
  plugin_trigger_event(params, hercules_domain(), GFAL_EVENT_NONE,
                       GFAL_EVENT_TRANSFER_EXIT, "Hercules finished transfer");
  return 0;
}

// Implementing stat seems to be required, it's called before transfers.
// The Hercules monitor has a /stat API endpoint for this.
int gfal_plugin_hercules_statG(plugin_handle h, const char *name,
                               struct stat *buf, GError **err) {
  struct gfal_hercules_context *data = (struct gfal_hercules_context *)h;

  GError *e = NULL;
  gfal2_context_t ctxt = gfal2_context_new(
      &e); // XXX No context argument to this function. I hope this is the right
           // way to get the certificate/key?
  if (e) {
    g_propagate_error(err, e);
    return -1;
  }
  gchar *user_cert = gfal2_cred_get(ctxt, GFAL_CRED_X509_CERT, name, NULL, &e);
  if (e || !user_cert) {
    gfal2_context_free(ctxt);
    g_propagate_error(err, e);
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_MESSAGE, "cert: %s", user_cert);
  g_clear_error(&e);
  if (data->user_cert) {
    free(data->user_cert);
    data->user_cert = NULL;
  }
  data->user_cert = user_cert;
  gchar *user_key = gfal2_cred_get(ctxt, GFAL_CRED_X509_KEY, name, NULL, &e);
  if (e || !user_key) {
    gfal2_context_free(ctxt);
    g_propagate_error(err, e);
    return -1;
  }
  gfal2_context_free(ctxt);
  g_clear_error(&e);
  if (data->user_key) {
    free(data->user_key);
    data->user_key = NULL;
  }
  data->user_key = user_key;
  gfal2_log(G_LOG_LEVEL_MESSAGE, "key: %s", user_key);

  // Parse the URL
  char url_host[500];
  char url_path[1000];
  int ret = sscanf(name, "hercules://%499[^/]/%999s", url_host, url_path);
  if (ret != 2) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error parsing source URL");
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_DEBUG, "Hercules: Checking %s %s", url_host, url_path);

  char request_url[2000];
  ret = snprintf(request_url, 2000, "https://%s/stat?file=%s", url_host,
                 url_path);
  if (ret >= 2000) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Submission URL too long");
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_DEBUG, "Hercules: Stat URL %s", request_url);

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__, "CURL error");
    return -1;
  }

  struct recvdata rec = {.size = 0};
  curl_easy_setopt(curl, CURLOPT_URL, request_url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recvfunc);
  curl_easy_setopt(curl, CURLOPT_SSLCERT, user_cert);
  curl_easy_setopt(curl, CURLOPT_SSLKEY, user_key);
  /* curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0); */
  /* curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0); */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rec);
  ret = curl_get_and_check(curl, err);
  if (ret) {
    curl_easy_cleanup(curl);
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_DEBUG, "Hercules: Stat Response %s", rec.response);

  unsigned long size;
  int ok;
  ret = sscanf(rec.response, "OK %d %ld", &ok, &size);
  if (ret != 2) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "Error parsing HTTP response?");
    curl_easy_cleanup(curl);
    return -1;
  }
  if (!ok) {
    gfal2_set_error(err, hercules_domain(), EINVAL, __func__,
                    "File does not exist or insufficient permissions");
    curl_easy_cleanup(curl);
    return -1;
  }
  gfal2_log(G_LOG_LEVEL_INFO, "Hercules: File size: %d", size);
  buf->st_size = size;
  curl_easy_cleanup(curl);
  return 0;
}
