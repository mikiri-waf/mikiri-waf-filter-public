/*
 * Proxying of the requests of the blocked clients through the captcha server.
 *
 * Instead of redirecting the client to the captcha, the filter forwards the
 * request to the captcha server, processes the "x-waf-captcha-challenge"
 * service header of the answer and either gives the captcha page back to the
 * client ("progress") or unbans the client and serves the page the client was
 * originally heading to ("complete").
 */

#include "waf_captcha.h"
#include "waf_captcha_compat.h"
#include "waf_request_parser.h"
#include "waf_exchange.h"
#include "waf_descriptions.h"

#include <ngx_event_connect.h>

#define WAF_CAPTCHA_CONNECT_TIMEOUT      5000
#define WAF_CAPTCHA_IO_TIMEOUT          15000
#define WAF_CAPTCHA_READ_INIT           32768
#define WAF_CAPTCHA_READ_STEP            4096
#define WAF_CAPTCHA_MAX_HEADER_BLOCK    65536
#define WAF_CAPTCHA_MAX_RESPONSE      2097152
#define WAF_CAPTCHA_MAX_HEADERS           128
#define WAF_CAPTCHA_LAST_STATUS           599
#define WAF_CAPTCHA_MAX_RETRIES             1
#define WAF_CAPTCHA_MAX_BODY            65536
#define WAF_CAPTCHA_ORIGIN_MAX           1024
#define WAF_CAPTCHA_COOKIE_TTL            300

#define WAF_CAPTCHA_IS(k, s)                                                  \
    (((k)->len == sizeof(s) - 1)                                              \
     && (ngx_strncasecmp((k)->data, (u_char *) s, sizeof(s) - 1) == 0))

static char redirect_html[] = 
"<head>" CRLF
"<meta http-equiv=\"refresh\" content=\"1;url=%V%s%V\">" CRLF
"</head>" CRLF
;

static ngx_str_t waf_captcha_challenge_hdr = ngx_string("x-waf-captcha-challenge");
static ngx_str_t waf_captcha_complete = ngx_string("complete");
static ngx_str_t waf_captcha_progress = ngx_string("progress");
static ngx_str_t waf_captcha_cookie = ngx_string("mikiri-waf-captcha");
static ngx_str_t waf_captcha_set_cookie_key = ngx_string("Set-Cookie");
static ngx_str_t waf_captcha_mlc_type = ngx_string("captcha");
static ngx_str_t waf_captcha_get_method = ngx_string("GET");
static ngx_str_t waf_captcha_root_path = ngx_string("/");
static ngx_str_t waf_captcha_https_schema = ngx_string("https");
static ngx_str_t waf_captcha_http_schema = ngx_string("http");

static ngx_str_t waf_captcha_hdr_ip = ngx_string("X-Waf-Captcha-Ip");
static ngx_str_t waf_captcha_hdr_host = ngx_string("X-Waf-Captcha-Host");
static ngx_str_t waf_captcha_hdr_path = ngx_string("X-Waf-Captcha-Path");
static ngx_str_t waf_captcha_hdr_schema = ngx_string("X-Waf-Captcha-Schema");
static ngx_str_t waf_captcha_hdr_iid = ngx_string("X-Waf-Captcha-Iid");

static ngx_int_t waf_captcha_get_peer(ngx_peer_connection_t *pc, void *data);
static void waf_captcha_cleanup(void *data);
static void waf_captcha_close(ngx_waf_captcha_ctx_t *cc);
static void waf_captcha_done(ngx_waf_captcha_ctx_t *cc, ngx_uint_t state);
static ngx_int_t waf_captcha_check_request(ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_fail(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                                  ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc);

static void waf_captcha_locate_origin(ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_build_request(ngx_http_waf_main_conf_t *wmc,
                                           ngx_http_request_ctx_t *rctx,
                                           ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_start(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                                   ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_connected(ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_send(ngx_waf_captcha_ctx_t *cc);
static void waf_captcha_write_handler(ngx_event_t *wev);
static void waf_captcha_read_handler(ngx_event_t *rev);

static ngx_int_t waf_captcha_parse_response(ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_parse_headers(ngx_waf_captcha_ctx_t *cc, u_char *start, u_char *end);
static ngx_int_t waf_captcha_parse_chunked(ngx_waf_captcha_ctx_t *cc);

static ngx_int_t waf_captcha_result(ngx_http_waf_main_conf_t *wmc,
                                    ngx_http_request_ctx_t *rctx, ngx_http_request_t *r,
                                    ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_reply(ngx_http_waf_main_conf_t *wmc,
                                   ngx_http_request_ctx_t *rctx, ngx_http_request_t *r,
                                   ngx_waf_captcha_ctx_t *cc);
static ngx_int_t waf_captcha_unban(ngx_http_waf_main_conf_t *wmc,
                                   ngx_http_request_ctx_t *rctx, ngx_http_request_t *r,
                                   ngx_waf_captcha_ctx_t *cc);

/* ------------------------------------------------------------------ */
/* configuration                                                       */
/* ------------------------------------------------------------------ */

/*
 * Splits the "waf_ban_captcha_url" value into the address to connect to,
 * the value of the Host header and the base path of the captcha application.
 */
ngx_int_t waf_captcha_parse_url(ngx_cycle_t *cycle, ngx_http_waf_main_conf_t *wmc) {
  ngx_waf_captcha_conf_t  *conf;
  ngx_str_t               src, hostport, path;
  ngx_url_t               *u;
  u_char                  *p, *last;
  ngx_flag_t              ssl;

  conf = &wmc->captcha_conf;

  conf->url = NULL;
  conf->ssl = 0;
  ngx_memzero(&conf->host, sizeof(ngx_str_t));
  ngx_memzero(&conf->sni, sizeof(ngx_str_t));
  ngx_memzero(&conf->path, sizeof(ngx_str_t));

  src = wmc->captcha_url;
  if ((src.data == NULL) || (src.len == 0)) {
    return NGX_OK;
  }

  ssl = 0;
  if ((src.len > 8) && (ngx_strncasecmp(src.data, (u_char *) "https://", 8) == 0)) {
    ssl = 1;
    src.data += 8;
    src.len -= 8;
  } else if ((src.len > 7) && (ngx_strncasecmp(src.data, (u_char *) "http://", 7) == 0)) {
    src.data += 7;
    src.len -= 7;
  }

  last = src.data + src.len;
  for (p = src.data; p < last; p++) {
    if (*p == '/') {
      break;
    }
  }

  hostport.data = src.data;
  hostport.len = p - src.data;
  path.data = p;
  path.len = last - p;

  if (hostport.len == 0) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_SET, wmc, NULL, NGX_LOG_ERR, cycle->log, 0,
                   STR_CAPTCHA_URL_INCORRECT, &wmc->captcha_url);
    return NGX_ERROR;
  }

  /* the base path is used as a prefix, the client URI already starts with "/" */
  while ((path.len > 0) && (path.data[path.len - 1] == '/')) {
    path.len--;
  }

#if !(NGX_SSL)
  if (ssl) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_SET, wmc, NULL, NGX_LOG_ERR, cycle->log, 0,
                   STR_CAPTCHA_NO_SSL, &wmc->captcha_url);
    return NGX_ERROR;
  }
#endif

  u = ngx_pcalloc(cycle->pool, sizeof(ngx_url_t));
  if (u == NULL) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, cycle->log, 0,
                   STR_NOT_ALLOC_U_D, sizeof(ngx_url_t), "cp1");
    return NGX_ERROR;
  }

  u->url.data = ngx_pcalloc(cycle->pool, hostport.len + 1);
  if (u->url.data == NULL) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, cycle->log, 0,
                   STR_NOT_ALLOC_U_D, hostport.len + 1, "cp2");
    return NGX_ERROR;
  }
  ngx_memcpy(u->url.data, hostport.data, hostport.len);
  u->url.len = hostport.len;
  u->default_port = (in_port_t) (ssl ? 443 : 80);

  if (ngx_parse_url(cycle->pool, u) != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_SET, wmc, NULL, NGX_LOG_ERR, cycle->log, 0,
                   STR_CAPTCHA_URL_RESOLVE, &wmc->captcha_url,
                   (u->err ? u->err : "unknown error"));
    return NGX_ERROR;
  }

  conf->host.data = u->url.data;
  conf->host.len = u->url.len;
  conf->sni = u->host;
  conf->ssl = ssl;

  if (path.len > 0) {
    conf->path.data = ngx_pcalloc(cycle->pool, path.len + 1);
    if (conf->path.data == NULL) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, cycle->log, 0,
                     STR_NOT_ALLOC_U_D, path.len + 1, "cp3");
      return NGX_ERROR;
    }
    ngx_memcpy(conf->path.data, path.data, path.len);
    conf->path.len = path.len;
  }

  conf->url = u;

  return NGX_OK;
}


ngx_flag_t waf_captcha_ready(ngx_http_waf_main_conf_t *wmc) {
  return (wmc->captcha_conf.url != NULL) ? 1 : 0;
}


#if (NGX_SSL)
static ngx_int_t waf_captcha_ssl_ctx(ngx_http_waf_main_conf_t *wmc) {
  ngx_ssl_t           *ssl;
  ngx_pool_cleanup_t  *cln;

  if (wmc->captcha_conf.ssl_ctx != NULL) {
    return NGX_OK;
  }

  ssl = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_ssl_t));
  if (ssl == NULL) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, ngx_cycle->log, 0,
                   STR_NOT_ALLOC_U_D, sizeof(ngx_ssl_t), "cp4");
    return NGX_ERROR;
  }
  ssl->log = ngx_cycle->log;

  if (ngx_ssl_create(ssl, NGX_SSL_DEFAULT_PROTOCOLS, NULL) != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, ngx_cycle->log, 0,
                   STR_CAPTCHA_SSL_INIT);
    return NGX_ERROR;
  }

  /*
   * The captcha server is a part of the installation and is reached by the
   * address taken from the settings, so its certificate is not verified:
   * a self-signed certificate is accepted without any diagnostics.
   */
  SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_NONE, NULL);

  cln = ngx_pool_cleanup_add(ngx_cycle->pool, 0);
  if (cln == NULL) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, ngx_cycle->log, 0,
                   STR_NOT_ALLOC_U_D, sizeof(ngx_pool_cleanup_t), "cp9");
    ngx_ssl_cleanup_ctx(ssl);
    return NGX_ERROR;
  }
  cln->handler = ngx_ssl_cleanup_ctx;
  cln->data = ssl;

  wmc->captcha_conf.ssl_ctx = ssl;

  return NGX_OK;
}
#endif


/* ------------------------------------------------------------------ */
/* connection helpers                                                  */
/* ------------------------------------------------------------------ */

static ngx_int_t waf_captcha_get_peer(ngx_peer_connection_t *pc, void *data) {
  return NGX_OK;
}


static void waf_captcha_close(ngx_waf_captcha_ctx_t *cc) {
  ngx_connection_t  *c;

  c = cc->peer.connection;
  if (c == NULL) {
    return;
  }
  cc->peer.connection = NULL;

#if (NGX_SSL)
  if (c->ssl) {
    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    (void) ngx_ssl_shutdown(c);
  }
#endif

  if (c->read->timer_set) {
    ngx_del_timer(c->read);
  }
  if (c->write->timer_set) {
    ngx_del_timer(c->write);
  }
  if (c->fd != (ngx_socket_t) -1) {
    ngx_close_connection(c);
  }
}


static void waf_captcha_cleanup(void *data) {
  ngx_waf_captcha_ctx_t  *cc = data;

  if (cc == NULL) {
    return;
  }
  cc->r = NULL;
  waf_captcha_close(cc);
}


/*
 * The captcha connection does not outlive the request it was created for:
 * waf_captcha_cleanup() drops the reference and closes the connection as
 * soon as the request is being freed.
 */
static ngx_int_t waf_captcha_check_request(ngx_waf_captcha_ctx_t *cc) {
  if ((cc->r == NULL) || (cc->r->pool == NULL)) {
    return NGX_ERROR;
  }
  return NGX_OK;
}


/*
 * Completes the exchange. When the exchange is driven from the request
 * handler the result is picked up by waf_captcha_proxy() itself, otherwise
 * the suspended request has to be resumed.
 */
static void waf_captcha_done(ngx_waf_captcha_ctx_t *cc, ngx_uint_t state) {
  ngx_http_request_t  *r;

  if (cc->finished) {
    return;
  }
  cc->finished = 1;
  cc->state = state;

  r = cc->r;

  waf_captcha_close(cc);

  if (cc->sync) {
    return;
  }
  if (waf_captcha_check_request(cc) != NGX_OK) {
    return;
  }

  ngx_http_core_run_phases(r);
}


/* the request is not suspended by the captcha exchange any more */
static void waf_captcha_undelay(ngx_http_request_t *r) {
  if (r->connection->write->timer_set) {
    ngx_del_timer(r->connection->write);
  }
  r->connection->write->delayed = 0;
  r->read_event_handler = ngx_http_block_reading;
  r->write_event_handler = ngx_http_core_run_phases;
}


static ngx_int_t waf_captcha_test_connect(ngx_connection_t *c) {
  int        err;
  socklen_t  len;

  err = 0;
  len = sizeof(int);

#if (NGX_HAVE_KQUEUE)
  if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
    if (c->write->pending_eof || c->read->pending_eof) {
      err = c->write->pending_eof ? c->write->kq_errno : c->read->kq_errno;
      (void) ngx_connection_error(c, err, "connect() failed");
      return NGX_ERROR;
    }
    return NGX_OK;
  }
#endif

  if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
    err = ngx_socket_errno;
  }
  if (err) {
    (void) ngx_connection_error(c, err, "connect() failed");
    return NGX_ERROR;
  }

  return NGX_OK;
}


/*
 * Makes room for "need" more bytes in the response buffer. All the pointers
 * kept into the buffer are moved along with its content.
 */
static ngx_int_t waf_captcha_reserve(ngx_waf_captcha_ctx_t *cc, size_t need) {
  ngx_keyval_t  *kv;
  ngx_uint_t    i;
  size_t        size, used, want;
  u_char        *p, *old;

  if (cc->in.start == NULL) {
    size = WAF_CAPTCHA_READ_INIT;
    p = ngx_palloc(cc->r->pool, size);
    if (p == NULL) {
      return NGX_ERROR;
    }
    cc->in.start = p;
    cc->in.pos = p;
    cc->in.last = p;
    cc->in.end = p + size;
    return NGX_OK;
  }

  if ((size_t) (cc->in.end - cc->in.last) >= need) {
    return NGX_OK;
  }

  old = cc->in.start;
  used = cc->in.last - old;
  size = cc->in.end - old;
  want = used + need;

  while (size < want) {
    size *= 2;
  }
  if (size > WAF_CAPTCHA_MAX_RESPONSE) {
    size = WAF_CAPTCHA_MAX_RESPONSE;
  }
  if (size < want) {
    return NGX_DECLINED;                        // the response is too large
  }

  p = ngx_palloc(cc->r->pool, size);
  if (p == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(p, old, used);

  if (cc->body_start != NULL) {
    cc->body_start = p + (cc->body_start - old);
  }
  if (cc->content_type.data != NULL) {
    cc->content_type.data = p + (cc->content_type.data - old);
  }
  if (cc->headers != NULL) {
    kv = cc->headers->elts;
    for (i = 0; i < cc->headers->nelts; i++) {
      kv[i].key.data = p + (kv[i].key.data - old);
      kv[i].value.data = p + (kv[i].value.data - old);
    }
  }

  cc->in.start = p;
  cc->in.pos = p;
  cc->in.last = p + used;
  cc->in.end = p + size;

  return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* the page the client was heading to                                  */
/* ------------------------------------------------------------------ */

static ngx_flag_t waf_captcha_origin_valid(ngx_str_t *uri) {
  size_t  i;

  if ((uri->len == 0) || (uri->len > WAF_CAPTCHA_ORIGIN_MAX)) {
    return 0;
  }
  if (uri->data[0] != '/') {
    return 0;
  }
  for (i = 0; i < uri->len; i++) {
    if ((uri->data[i] <= 0x20) || (uri->data[i] >= 0x7f)) {
      return 0;
    }
    if ((uri->data[i] == '.') && (i + 1 < uri->len) && (uri->data[i + 1] == '.')) {
      return 0;
    }
  }
  return 1;
}


static ngx_flag_t waf_captcha_args_valid(ngx_str_t *args) {
  size_t  i;

  if (args->len > WAF_CAPTCHA_ORIGIN_MAX) {
    return 0;
  }
  for (i = 0; i < args->len; i++) {
    if ((args->data[i] <= 0x20) || (args->data[i] >= 0x7f)) {
      return 0;
    }
  }
  return 1;
}


/*
 * The original URI is carried between the captcha steps in a client cookie,
 * the value is "<base64 uri>.<base64 args>".
 */
static void waf_captcha_locate_origin(ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc) {
  ngx_str_t  name, value, part, uri, args;
  u_char     *p, *last;

  cc->origin_stored = 0;
  ngx_memzero(&uri, sizeof(ngx_str_t));
  ngx_memzero(&args, sizeof(ngx_str_t));

  name = waf_captcha_cookie;

  if (waf_captcha_find_cookie(r, &name, &value) != NULL) {

    last = value.data + value.len;
    for (p = value.data; p < last; p++) {
      if (*p == '.') {
        break;
      }
    }

    if (p < last) {
      uri.len = ngx_base64_decoded_length(p - value.data);
      uri.data = ngx_pnalloc(r->pool, uri.len + 1);

      args.len = ngx_base64_decoded_length(last - (p + 1));
      args.data = ngx_pnalloc(r->pool, args.len + 1);

      if ((uri.data != NULL) && (args.data != NULL)) {
        part.data = value.data;
        part.len = p - value.data;

        if (ngx_decode_base64(&uri, &part) == NGX_OK) {
          part.data = p + 1;
          part.len = last - (p + 1);

          if (ngx_decode_base64(&args, &part) == NGX_OK) {
            if (waf_captcha_origin_valid(&uri) && waf_captcha_args_valid(&args)) {
              cc->origin_uri = uri;
              cc->origin_args = args;
              cc->origin_stored = 1;
            }
          }
        }
      }
    }
  }

  if (!cc->origin_stored) {
    cc->origin_uri = r->uri;
    cc->origin_args = r->args;

    if (!waf_captcha_origin_valid(&cc->origin_uri)) {
      cc->origin_uri = waf_captcha_root_path;
      ngx_memzero(&cc->origin_args, sizeof(ngx_str_t));
    }
    if (!waf_captcha_args_valid(&cc->origin_args)) {
      ngx_memzero(&cc->origin_args, sizeof(ngx_str_t));
    }
  }

  cc->origin.len = cc->origin_uri.len + (cc->origin_args.len ? cc->origin_args.len + 1 : 0);
  cc->origin.data = ngx_pnalloc(r->pool, cc->origin.len + 1);
  if (cc->origin.data == NULL) {
    cc->origin.len = 0;
    return;
  }
  p = ngx_cpymem(cc->origin.data, cc->origin_uri.data, cc->origin_uri.len);
  if (cc->origin_args.len) {
    *p++ = '?';
    p = ngx_cpymem(p, cc->origin_args.data, cc->origin_args.len);
  }
  *p = '\0';
}


static ngx_int_t waf_captcha_set_cookie(ngx_http_request_ctx_t *rctx, ngx_http_request_t *r,
                                        ngx_waf_captcha_ctx_t *cc) {
  ngx_table_elt_t  *h;
  ngx_str_t        b64uri, b64args;
  size_t           len;
  u_char           *p;
  ngx_flag_t       secure;

  b64uri.len = ngx_base64_encoded_length(cc->origin_uri.len);
  b64uri.data = ngx_pnalloc(r->pool, b64uri.len + 1);
  if (b64uri.data == NULL) {
    return NGX_ERROR;
  }
  ngx_encode_base64(&b64uri, &cc->origin_uri);

  b64args.len = ngx_base64_encoded_length(cc->origin_args.len);
  b64args.data = ngx_pnalloc(r->pool, b64args.len + 1);
  if (b64args.data == NULL) {
    return NGX_ERROR;
  }
  ngx_encode_base64(&b64args, &cc->origin_args);

  secure = 0;
  if ((rctx->schema.len == waf_captcha_https_schema.len)
      && (ngx_strncasecmp(rctx->schema.data, waf_captcha_https_schema.data,
                          waf_captcha_https_schema.len) == 0)) {
    secure = 1;
  }

  len = waf_captcha_cookie.len + 1 + b64uri.len + 1 + b64args.len
        + sizeof("; Path=/; Max-Age=; HttpOnly; SameSite=Lax") - 1 + NGX_INT_T_LEN
        + sizeof("; Secure") - 1;

  p = ngx_pnalloc(r->pool, len + 1);
  if (p == NULL) {
    return NGX_ERROR;
  }

  h = ngx_list_push(&r->headers_out.headers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  h->hash = 1;
  h->next = NULL;
  h->key = waf_captcha_set_cookie_key;
  h->lowcase_key = (u_char *) "set-cookie";
  h->value.data = p;

  p = ngx_sprintf(p, "%V=%V.%V; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax",
                  &waf_captcha_cookie, &b64uri, &b64args, WAF_CAPTCHA_COOKIE_TTL);
  if (secure) {
    p = ngx_cpymem(p, "; Secure", sizeof("; Secure") - 1);
  }
  *p = '\0';
  h->value.len = p - h->value.data;

  return NGX_OK;
}


/*
 * Removes the captcha cookie from the request so that it is never given
 * away to the protected application.
 */
static void waf_captcha_strip_cookie(ngx_http_request_t *r) {
  ngx_table_elt_t  *h;
  u_char           *start, *end, *pair, *pend, *cut;

  for (h = r->headers_in.cookie; h; h = h->next) {

    if (h->hash == 0) {
      continue;
    }

    start = h->value.data;
    end = start + h->value.len;
    pair = start;

    while (pair < end) {

      while ((pair < end) && ((*pair == ' ') || (*pair == ';'))) {
        pair++;
      }
      if (pair >= end) {
        break;
      }

      pend = pair;
      while ((pend < end) && (*pend != ';')) {
        pend++;
      }

      if (((size_t) (pend - pair) > waf_captcha_cookie.len)
          && (ngx_strncmp(pair, waf_captcha_cookie.data, waf_captcha_cookie.len) == 0)
          && (pair[waf_captcha_cookie.len] == '=')) {

        cut = pend;
        while ((cut < end) && ((*cut == ';') || (*cut == ' '))) {
          cut++;
        }
        if (cut < end) {
          ngx_memmove(pair, cut, end - cut);
        }
        end -= (cut - pair);
        continue;
      }

      pair = pend;
    }

    while ((end > start) && ((*(end - 1) == ';') || (*(end - 1) == ' '))) {
      end--;
    }

    h->value.len = end - start;
    if (h->value.len == 0) {
      h->hash = 0;
    }
  }
}


/* ------------------------------------------------------------------ */
/* the request to the captcha server                                   */
/* ------------------------------------------------------------------ */

static ngx_flag_t waf_captcha_skip_request_header(ngx_str_t *k) {
  if (WAF_CAPTCHA_IS(k, "host")
      || WAF_CAPTCHA_IS(k, "connection")
      || WAF_CAPTCHA_IS(k, "keep-alive")
      || WAF_CAPTCHA_IS(k, "proxy-connection")
      || WAF_CAPTCHA_IS(k, "proxy-authorization")
      || WAF_CAPTCHA_IS(k, "transfer-encoding")
      || WAF_CAPTCHA_IS(k, "content-length")
      || WAF_CAPTCHA_IS(k, "accept-encoding")
      || WAF_CAPTCHA_IS(k, "expect")
      || WAF_CAPTCHA_IS(k, "upgrade")
      || WAF_CAPTCHA_IS(k, "te")) {
    return 1;
  }
  /* the client must not be able to forge the service headers */
  if ((k->len >= sizeof("x-waf-captcha-") - 1)
      && (ngx_strncasecmp(k->data, (u_char *) "x-waf-captcha-",
                          sizeof("x-waf-captcha-") - 1) == 0)) {
    return 1;
  }
  return 0;
}


static u_char *waf_captcha_write_value(u_char *p, ngx_str_t *v) {
  size_t  i;

  for (i = 0; i < v->len; i++) {
    if ((v->data[i] >= 0x20) && (v->data[i] < 0x7f)) {
      *p++ = v->data[i];
    }
  }
  return p;
}


static ngx_int_t waf_captcha_build_request(ngx_http_waf_main_conf_t *wmc,
                                           ngx_http_request_ctx_t *rctx,
                                           ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc) {
  ngx_waf_captcha_conf_t  *conf;
  ngx_list_part_t         *part;
  ngx_table_elt_t         *h;
  ngx_chain_t             *cl;
  ngx_keyval_t            svc[5];
  ngx_str_t               method, target, uri, schema;
  ngx_uint_t              i, nsvc;
  size_t                  len, body_len;
  u_char                  *p;

  conf = &wmc->captcha_conf;
  body_len = 0;

  if (cc->page_only) {
    method = waf_captcha_get_method;
    uri = waf_captcha_root_path;

  } else {
    method = r->method_name;

    if (r->unparsed_uri.len > 0) {
      uri = r->unparsed_uri;

    } else if (r->args.len > 0) {
      uri.len = r->uri.len + 1 + r->args.len;
      uri.data = ngx_pnalloc(r->pool, uri.len);
      if (uri.data == NULL) {
        waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                       STR_NOT_ALLOC_U_D, uri.len, "cp11");
        return NGX_ERROR;
      }
      p = ngx_cpymem(uri.data, r->uri.data, r->uri.len);
      *p++ = '?';
      ngx_memcpy(p, r->args.data, r->args.len);

    } else {
      uri = r->uri;
    }

    if ((r->request_body != NULL) && (r->request_body->temp_file == NULL)) {
      for (cl = r->request_body->bufs; cl; cl = cl->next) {
        body_len += cl->buf->last - cl->buf->pos;
      }
      /* the captcha only ever needs its own small forms */
      if (body_len > WAF_CAPTCHA_MAX_BODY) {
        body_len = 0;
      }
    }
  }

  if ((uri.len == 0) || (uri.data[0] != '/')) {
    uri = waf_captcha_root_path;
  }

  target.len = conf->path.len + uri.len;
  target.data = ngx_pnalloc(r->pool, target.len);
  if (target.data == NULL) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                   STR_NOT_ALLOC_U_D, target.len, "cp12");
    return NGX_ERROR;
  }
  p = ngx_cpymem(target.data, conf->path.data, conf->path.len);
  ngx_memcpy(p, uri.data, uri.len);

  schema = waf_captcha_http_schema;
  if ((rctx->schema.len == waf_captcha_https_schema.len)
      && (ngx_strncasecmp(rctx->schema.data, waf_captcha_https_schema.data,
                          waf_captcha_https_schema.len) == 0)) {
    schema = waf_captcha_https_schema;
  }

  nsvc = 0;
  svc[nsvc].key = waf_captcha_hdr_ip;
  svc[nsvc++].value = r->connection->addr_text;
  svc[nsvc].key = waf_captcha_hdr_host;
  svc[nsvc++].value = r->headers_in.server;
  svc[nsvc].key = waf_captcha_hdr_path;
  svc[nsvc++].value = cc->origin;
  svc[nsvc].key = waf_captcha_hdr_schema;
  svc[nsvc++].value = schema;
  svc[nsvc].key = waf_captcha_hdr_iid;
  svc[nsvc++].value = wmc->iid;

  len = method.len + 1 + target.len + sizeof(" HTTP/1.1" CRLF) - 1
        + sizeof("Host: ") - 1 + conf->host.len + sizeof(CRLF) - 1
        + sizeof("Connection: close" CRLF) - 1
        + sizeof("Content-Length: ") - 1 + NGX_SIZE_T_LEN + sizeof(CRLF) - 1
        + sizeof(CRLF) - 1
        + body_len;

  for (i = 0; i < nsvc; i++) {
    len += svc[i].key.len + 2 + svc[i].value.len + sizeof(CRLF) - 1;
  }

  part = &r->headers_in.headers.part;
  h = part->elts;
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      h = part->elts;
      i = 0;
    }
    if (h[i].hash == 0) {
      continue;
    }
    if (waf_captcha_skip_request_header(&h[i].key)) {
      continue;
    }
    if ((body_len == 0) && WAF_CAPTCHA_IS(&h[i].key, "content-type")) {
      continue;
    }
    len += h[i].key.len + 2 + h[i].value.len + sizeof(CRLF) - 1;
  }

  cc->out.start = ngx_pnalloc(r->pool, len);
  if (cc->out.start == NULL) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                   STR_NOT_ALLOC_U_D, len, "cp5");
    return NGX_ERROR;
  }
  p = cc->out.start;

  p = ngx_cpymem(p, method.data, method.len);
  *p++ = ' ';
  p = ngx_cpymem(p, target.data, target.len);
  p = ngx_cpymem(p, " HTTP/1.1" CRLF, sizeof(" HTTP/1.1" CRLF) - 1);

  p = ngx_cpymem(p, "Host: ", sizeof("Host: ") - 1);
  p = ngx_cpymem(p, conf->host.data, conf->host.len);
  p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);

  p = ngx_cpymem(p, "Connection: close" CRLF, sizeof("Connection: close" CRLF) - 1);
  p = ngx_sprintf(p, "Content-Length: %uz" CRLF, body_len);

  for (i = 0; i < nsvc; i++) {
    p = ngx_cpymem(p, svc[i].key.data, svc[i].key.len);
    *p++ = ':';
    *p++ = ' ';
    p = waf_captcha_write_value(p, &svc[i].value);
    p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);
  }

  part = &r->headers_in.headers.part;
  h = part->elts;
  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      h = part->elts;
      i = 0;
    }
    if (h[i].hash == 0) {
      continue;
    }
    if (waf_captcha_skip_request_header(&h[i].key)) {
      continue;
    }
    if ((body_len == 0) && WAF_CAPTCHA_IS(&h[i].key, "content-type")) {
      continue;
    }
    p = ngx_cpymem(p, h[i].key.data, h[i].key.len);
    *p++ = ':';
    *p++ = ' ';
    p = waf_captcha_write_value(p, &h[i].value);
    p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);
  }

  p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);

  if (body_len > 0) {
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
      p = ngx_cpymem(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
    }
  }

  cc->out.pos = cc->out.start;
  cc->out.last = p;
  cc->out.end = p;

  return NGX_OK;
}


/* ------------------------------------------------------------------ */
/* the exchange                                                        */
/* ------------------------------------------------------------------ */

static ngx_int_t waf_captcha_start(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                                   ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc) {
  ngx_waf_captcha_conf_t  *conf;
  ngx_connection_t        *c;
  ngx_int_t               rc;

  conf = &wmc->captcha_conf;

  cc->state = WAF_CAPTCHA_ST_CONNECT;
  cc->finished = 0;
  cc->eof = 0;
  cc->headers_parsed = 0;
  cc->body_start = NULL;
  cc->content_length = -1;
  cc->chunked = 0;
  cc->status = 0;
  cc->pass = WAF_CAPTCHA_PASS_NONE;
  cc->headers = NULL;
  ngx_memzero(&cc->in, sizeof(ngx_buf_t));
  ngx_memzero(&cc->out, sizeof(ngx_buf_t));
  ngx_memzero(&cc->body, sizeof(ngx_str_t));
  ngx_memzero(&cc->content_type, sizeof(ngx_str_t));

  if (waf_captcha_build_request(wmc, rctx, r, cc) != NGX_OK) {
    return NGX_ERROR;
  }

  ngx_memzero(&cc->peer, sizeof(ngx_peer_connection_t));
  cc->peer.sockaddr = &conf->url->sockaddr.sockaddr;
  cc->peer.socklen = conf->url->socklen;
  cc->peer.name = &conf->host;
  cc->peer.get = waf_captcha_get_peer;
  cc->peer.log = r->connection->log;
  cc->peer.log_error = NGX_ERROR_ERR;

  rc = ngx_event_connect_peer(&cc->peer);

  if ((rc == NGX_ERROR) || (rc == NGX_BUSY) || (rc == NGX_DECLINED)) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                   STR_CAPTCHA_CONNECT, &conf->host, &rctx->req_id_s);
    if (cc->peer.connection != NULL) {
      ngx_close_connection(cc->peer.connection);
      cc->peer.connection = NULL;
    }
    return NGX_ERROR;
  }

  c = cc->peer.connection;
  c->data = cc;
  c->pool = r->pool;
  c->log = r->connection->log;
  c->read->log = c->log;
  c->write->log = c->log;
  c->sendfile = 0;
  c->read->handler = waf_captcha_read_handler;
  c->write->handler = waf_captcha_write_handler;

  if (rc == NGX_AGAIN) {
    ngx_add_timer(c->write, WAF_CAPTCHA_CONNECT_TIMEOUT);
    return NGX_OK;
  }

  return waf_captcha_connected(cc);
}


#if (NGX_SSL)
static void waf_captcha_ssl_handshake_handler(ngx_connection_t *c);


static ngx_int_t waf_captcha_ssl_init(ngx_waf_captcha_ctx_t *cc) {
  ngx_connection_t          *c;
  ngx_http_waf_main_conf_t  *wmc;
  ngx_int_t                 rc;

  c = cc->peer.connection;
  wmc = ngx_http_get_module_main_conf(cc->r, mikiri_waf_http_module);

  if (waf_captcha_ssl_ctx(wmc) != NGX_OK) {
    return NGX_ERROR;
  }

  if (ngx_ssl_create_connection(wmc->captcha_conf.ssl_ctx, c,
                                NGX_SSL_BUFFER|NGX_SSL_CLIENT) != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_SSL_CONN, &wmc->captcha_conf.host);
    return NGX_ERROR;
  }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if ((wmc->captcha_conf.sni.len > 0)
      && (ngx_inet_addr(wmc->captcha_conf.sni.data,
                        wmc->captcha_conf.sni.len) == INADDR_NONE))
  {
    u_char  *sni;

    sni = ngx_pnalloc(cc->r->pool, wmc->captcha_conf.sni.len + 1);
    if (sni == NULL) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                     STR_NOT_ALLOC_U_D, wmc->captcha_conf.sni.len + 1, "cp10");
      return NGX_ERROR;
    }
    ngx_memcpy(sni, wmc->captcha_conf.sni.data, wmc->captcha_conf.sni.len);
    sni[wmc->captcha_conf.sni.len] = '\0';

    if (SSL_set_tlsext_host_name(c->ssl->connection, (char *) sni) == 0) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                     STR_CAPTCHA_SSL_CONN, &wmc->captcha_conf.host);
      return NGX_ERROR;
    }
  }
#endif

  cc->state = WAF_CAPTCHA_ST_HANDSHAKE;

  rc = ngx_ssl_handshake(c);

  if (rc == NGX_AGAIN) {
    c->ssl->handler = waf_captcha_ssl_handshake_handler;
    ngx_add_timer(c->write, WAF_CAPTCHA_IO_TIMEOUT);
    return NGX_OK;
  }

  if (rc != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_SSL_HANDSHAKE, &wmc->captcha_conf.host);
    return NGX_ERROR;
  }

  cc->state = WAF_CAPTCHA_ST_SEND;

  if (waf_captcha_send(cc) != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_SEND, &wmc->captcha_conf.host);
    return NGX_ERROR;
  }

  return NGX_OK;
}


static void waf_captcha_ssl_handshake_handler(ngx_connection_t *c) {
  ngx_waf_captcha_ctx_t     *cc;
  ngx_http_waf_main_conf_t  *wmc;

  cc = c->data;

  if (waf_captcha_check_request(cc) != NGX_OK) {
    waf_captcha_close(cc);
    return;
  }

  wmc = ngx_http_get_module_main_conf(cc->r, mikiri_waf_http_module);

  if (c->read->timer_set) {
    ngx_del_timer(c->read);
  }
  if (c->write->timer_set) {
    ngx_del_timer(c->write);
  }

  c->read->handler = waf_captcha_read_handler;
  c->write->handler = waf_captcha_write_handler;

  if (!c->ssl->handshaked) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_SSL_HANDSHAKE, &wmc->captcha_conf.host);
    waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
    return;
  }

  cc->state = WAF_CAPTCHA_ST_SEND;

  if (waf_captcha_send(cc) != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_SEND, &wmc->captcha_conf.host);
    waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
  }
}
#endif


static ngx_int_t waf_captcha_connected(ngx_waf_captcha_ctx_t *cc) {
  ngx_connection_t          *c;
  ngx_http_waf_main_conf_t  *wmc;
  ngx_http_request_ctx_t    *rctx;

  c = cc->peer.connection;
  wmc = ngx_http_get_module_main_conf(cc->r, mikiri_waf_http_module);
  rctx = ngx_http_get_module_ctx(cc->r, mikiri_waf_http_module);

  if (waf_captcha_test_connect(c) != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_CONNECT, &wmc->captcha_conf.host,
                   (rctx ? &rctx->req_id_s : &cc->r->connection->addr_text));
    return NGX_ERROR;
  }

#if (NGX_SSL)
  if (wmc->captcha_conf.ssl && (c->ssl == NULL)) {
    return waf_captcha_ssl_init(cc);
  }
#endif

  cc->state = WAF_CAPTCHA_ST_SEND;

  if (waf_captcha_send(cc) != NGX_OK) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_SEND, &wmc->captcha_conf.host);
    return NGX_ERROR;
  }

  return NGX_OK;
}


static ngx_int_t waf_captcha_send(ngx_waf_captcha_ctx_t *cc) {
  ngx_connection_t  *c;
  ssize_t           n;

  c = cc->peer.connection;

  while (cc->out.pos < cc->out.last) {

    n = c->send(c, cc->out.pos, cc->out.last - cc->out.pos);

    if (n == NGX_AGAIN) {
      if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
      }
      if (!c->write->timer_set) {
        ngx_add_timer(c->write, WAF_CAPTCHA_IO_TIMEOUT);
      }
      return NGX_OK;
    }

    if (n == NGX_ERROR) {
      return NGX_ERROR;
    }

    cc->out.pos += n;
  }

  if (c->write->timer_set) {
    ngx_del_timer(c->write);
  }

  cc->state = WAF_CAPTCHA_ST_READ;

  if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
    return NGX_ERROR;
  }
  if (!c->read->timer_set) {
    ngx_add_timer(c->read, WAF_CAPTCHA_IO_TIMEOUT);
  }

  if (c->read->ready) {
    waf_captcha_read_handler(c->read);
  }

  return NGX_OK;
}


static void waf_captcha_write_handler(ngx_event_t *wev) {
  ngx_connection_t          *c;
  ngx_waf_captcha_ctx_t     *cc;
  ngx_http_waf_main_conf_t  *wmc;

  c = wev->data;
  cc = c->data;

  if (waf_captcha_check_request(cc) != NGX_OK) {
    waf_captcha_close(cc);
    return;
  }

  wmc = ngx_http_get_module_main_conf(cc->r, mikiri_waf_http_module);

  if (wev->timedout) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_TIMEOUT, &wmc->captcha_conf.host);
    waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
    return;
  }

  if (cc->state == WAF_CAPTCHA_ST_CONNECT) {
    if (wev->timer_set) {
      ngx_del_timer(wev);
    }
    if (waf_captcha_connected(cc) != NGX_OK) {
      waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
    }
    return;
  }

  if (cc->state == WAF_CAPTCHA_ST_SEND) {
    if (waf_captcha_send(cc) != NGX_OK) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                     STR_CAPTCHA_SEND, &wmc->captcha_conf.host);
      waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
    }
    return;
  }
}


static void waf_captcha_read_handler(ngx_event_t *rev) {
  ngx_connection_t          *c;
  ngx_waf_captcha_ctx_t     *cc;
  ngx_http_waf_main_conf_t  *wmc;
  ngx_int_t                 rc;
  ssize_t                   n;

  c = rev->data;
  cc = c->data;

  if (waf_captcha_check_request(cc) != NGX_OK) {
    waf_captcha_close(cc);
    return;
  }

  wmc = ngx_http_get_module_main_conf(cc->r, mikiri_waf_http_module);

  if (rev->timedout) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_TIMEOUT, &wmc->captcha_conf.host);
    waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
    return;
  }

  if (cc->state != WAF_CAPTCHA_ST_READ) {
    return;
  }

  for ( ;; ) {

    rc = waf_captcha_reserve(cc, WAF_CAPTCHA_READ_STEP);

    if (rc == NGX_DECLINED) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                     STR_CAPTCHA_TOO_LARGE, &wmc->captcha_conf.host, WAF_CAPTCHA_MAX_RESPONSE);
      rc = NGX_ERROR;
      break;
    }
    if (rc != NGX_OK) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                     STR_NOT_ALLOC_U_D, WAF_CAPTCHA_READ_STEP, "cp13");
      rc = NGX_ERROR;
      break;
    }

    n = c->recv(c, cc->in.last, cc->in.end - cc->in.last);

    if (n > 0) {
      cc->in.last += n;
      rc = waf_captcha_parse_response(cc);
      if (rc == NGX_ERROR) {
        waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                       STR_CAPTCHA_READ, &wmc->captcha_conf.host);
      }
      if (rc != NGX_AGAIN) {
        break;
      }
      continue;
    }

    if (n == 0) {
      cc->eof = 1;
      rc = waf_captcha_parse_response(cc);
      if (rc != NGX_OK) {
        waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                       STR_CAPTCHA_READ, &wmc->captcha_conf.host);
        rc = NGX_ERROR;
      }
      break;
    }

    if (n == NGX_AGAIN) {
      rc = NGX_AGAIN;
      break;
    }

    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, ngx_socket_errno,
                   STR_CAPTCHA_READ, &wmc->captcha_conf.host);
    rc = NGX_ERROR;
    break;
  }

  if (rc == NGX_AGAIN) {
    if (ngx_handle_read_event(rev, 0) == NGX_OK) {
      if (!rev->timer_set) {
        ngx_add_timer(rev, WAF_CAPTCHA_IO_TIMEOUT);
      }
      return;
    }
    waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, c->log, 0,
                   STR_CAPTCHA_READ, &wmc->captcha_conf.host);
    rc = NGX_ERROR;
  }

  if (rc == NGX_OK) {
    waf_captcha_done(cc, WAF_CAPTCHA_ST_READY);
    return;
  }

  waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
}


/* ------------------------------------------------------------------ */
/* the answer of the captcha server                                    */
/* ------------------------------------------------------------------ */

static ngx_flag_t waf_captcha_skip_response_header(ngx_str_t *k) {
  if (WAF_CAPTCHA_IS(k, "connection")
      || WAF_CAPTCHA_IS(k, "keep-alive")
      || WAF_CAPTCHA_IS(k, "transfer-encoding")
      || WAF_CAPTCHA_IS(k, "content-length")
      || WAF_CAPTCHA_IS(k, "date")
      || WAF_CAPTCHA_IS(k, "server")) {
    return 1;
  }
  return 0;
}


static ngx_int_t waf_captcha_parse_headers(ngx_waf_captcha_ctx_t *cc, u_char *start, u_char *end) {
  ngx_keyval_t  *kv;
  ngx_str_t     key, value;
  u_char        *p, *line, *eol, *colon;

  p = start;

  /* status line */
  for (eol = p; eol < end; eol++) {
    if (*eol == CR) {
      break;
    }
  }
  if ((eol - p) < (ssize_t) (sizeof("HTTP/1.0 200") - 1)) {
    return NGX_ERROR;
  }
  if (ngx_strncasecmp(p, (u_char *) "HTTP/", sizeof("HTTP/") - 1) != 0) {
    return NGX_ERROR;
  }

  line = p;
  while ((line < eol) && (*line != ' ')) {
    line++;
  }
  while ((line < eol) && (*line == ' ')) {
    line++;
  }
  if ((eol - line) < 3) {
    return NGX_ERROR;
  }
  if ((line[0] < '0') || (line[0] > '9') || (line[1] < '0') || (line[1] > '9')
      || (line[2] < '0') || (line[2] > '9')) {
    return NGX_ERROR;
  }
  cc->status = (ngx_uint_t) ((line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0'));

  cc->headers = ngx_array_create(cc->r->pool, 8, sizeof(ngx_keyval_t));
  if (cc->headers == NULL) {
    return NGX_ERROR;
  }

  p = eol + 2;

  while (p < end) {

    for (eol = p; eol < end; eol++) {
      if (*eol == CR) {
        break;
      }
    }
    if (eol == p) {
      break;
    }

    colon = p;
    while ((colon < eol) && (*colon != ':')) {
      colon++;
    }
    if (colon == eol) {
      p = eol + 2;
      continue;
    }

    key.data = p;
    key.len = colon - p;
    while ((key.len > 0) && (key.data[key.len - 1] == ' ')) {
      key.len--;
    }

    value.data = colon + 1;
    while ((value.data < eol) && ((*value.data == ' ') || (*value.data == '\t'))) {
      value.data++;
    }
    value.len = eol - value.data;
    while ((value.len > 0)
           && ((value.data[value.len - 1] == ' ') || (value.data[value.len - 1] == '\t'))) {
      value.len--;
    }

    p = eol + 2;

    if (key.len == 0) {
      continue;
    }

    if ((key.len == waf_captcha_challenge_hdr.len)
        && (ngx_strncasecmp(key.data, waf_captcha_challenge_hdr.data,
                            waf_captcha_challenge_hdr.len) == 0)) {

      if ((value.len == waf_captcha_complete.len)
          && (ngx_strncasecmp(value.data, waf_captcha_complete.data,
                              waf_captcha_complete.len) == 0)) {
        cc->pass = WAF_CAPTCHA_PASS_COMPLETE;

      } else if ((value.len == waf_captcha_progress.len)
                 && (ngx_strncasecmp(value.data, waf_captcha_progress.data,
                                     waf_captcha_progress.len) == 0)) {
        cc->pass = WAF_CAPTCHA_PASS_PROGRESS;
      }
      /* the service header is never given away to the client */
      continue;
    }

    if (WAF_CAPTCHA_IS(&key, "content-length")) {
      cc->content_length = ngx_atoof(value.data, value.len);
      continue;
    }

    if (WAF_CAPTCHA_IS(&key, "transfer-encoding")) {
      if (ngx_strlcasestrn(value.data, value.data + value.len,
                           (u_char *) "chunked", sizeof("chunked") - 2) != NULL) {
        cc->chunked = 1;
      }
      continue;
    }

    if (WAF_CAPTCHA_IS(&key, "content-type")) {
      cc->content_type = value;
      continue;
    }

    if (waf_captcha_skip_response_header(&key)) {
      continue;
    }

    if (cc->headers->nelts >= WAF_CAPTCHA_MAX_HEADERS) {
      continue;
    }

    kv = ngx_array_push(cc->headers);
    if (kv == NULL) {
      return NGX_ERROR;
    }
    kv->key = key;
    kv->value = value;
  }

  return NGX_OK;
}


static ngx_int_t waf_captcha_chunked_scan(ngx_waf_captcha_ctx_t *cc, u_char *dst, size_t *total) {
  u_char      *p, *last;
  size_t      size;
  ngx_uint_t  digits;
  ngx_int_t   d;

  p = cc->body_start;
  last = cc->in.last;
  *total = 0;

  for ( ;; ) {

    size = 0;
    digits = 0;

    while (p < last) {
      if ((*p == CR) || (*p == ';')) {
        break;
      }
      if ((*p >= '0') && (*p <= '9')) {
        d = *p - '0';
      } else if ((*p >= 'a') && (*p <= 'f')) {
        d = *p - 'a' + 10;
      } else if ((*p >= 'A') && (*p <= 'F')) {
        d = *p - 'A' + 10;
      } else {
        return NGX_ERROR;
      }
      if (digits >= 8) {
        return NGX_ERROR;
      }
      size = (size << 4) + (size_t) d;
      digits++;
      p++;
    }

    if (digits == 0) {
      return (p >= last) ? NGX_AGAIN : NGX_ERROR;
    }

    while ((p < last) && (*p != CR)) {
      p++;
    }
    if ((last - p) < 2) {
      return NGX_AGAIN;
    }
    if ((p[0] != CR) || (p[1] != LF)) {
      return NGX_ERROR;
    }
    p += 2;

    if (size == 0) {
      break;
    }

    if ((size_t) (last - p) < size + 2) {
      return NGX_AGAIN;
    }
    if ((p[size] != CR) || (p[size + 1] != LF)) {
      return NGX_ERROR;
    }

    if (dst != NULL) {
      dst = ngx_cpymem(dst, p, size);
    }
    *total += size;

    p += size + 2;
  }

  return NGX_OK;
}


static ngx_int_t waf_captcha_parse_chunked(ngx_waf_captcha_ctx_t *cc) {
  ngx_int_t  rc;
  size_t     total;
  u_char     *out;

  rc = waf_captcha_chunked_scan(cc, NULL, &total);
  if (rc == NGX_AGAIN) {
    return cc->eof ? NGX_ERROR : NGX_AGAIN;
  }
  if (rc != NGX_OK) {
    return NGX_ERROR;
  }

  out = ngx_pnalloc(cc->r->pool, total + 1);
  if (out == NULL) {
    return NGX_ERROR;
  }

  rc = waf_captcha_chunked_scan(cc, out, &total);
  if (rc != NGX_OK) {
    return NGX_ERROR;
  }

  cc->body.data = out;
  cc->body.len = total;

  return NGX_OK;
}


static ngx_int_t waf_captcha_parse_response(ngx_waf_captcha_ctx_t *cc) {
  u_char  *p, *last;
  size_t  avail;

  if (!cc->headers_parsed) {

    last = cc->in.last;
    for (p = cc->in.start; (p + 3) < last; p++) {
      if ((p[0] == CR) && (p[1] == LF) && (p[2] == CR) && (p[3] == LF)) {
        break;
      }
    }

    if ((p + 3) >= last) {
      if (cc->eof) {
        return NGX_ERROR;
      }
      if ((size_t) (cc->in.last - cc->in.start) > WAF_CAPTCHA_MAX_HEADER_BLOCK) {
        return NGX_ERROR;
      }
      return NGX_AGAIN;
    }

    if (waf_captcha_parse_headers(cc, cc->in.start, p) != NGX_OK) {
      return NGX_ERROR;
    }

    cc->headers_parsed = 1;
    cc->body_start = p + 4;
  }

  if ((cc->status == NGX_HTTP_NO_CONTENT) || (cc->status == NGX_HTTP_NOT_MODIFIED)
      || (cc->status < NGX_HTTP_OK)) {
    cc->body.data = cc->body_start;
    cc->body.len = 0;
    return NGX_OK;
  }

  if (cc->chunked) {
    return waf_captcha_parse_chunked(cc);
  }

  avail = cc->in.last - cc->body_start;

  if (cc->content_length >= 0) {
    if (avail >= (size_t) cc->content_length) {
      cc->body.data = cc->body_start;
      cc->body.len = (size_t) cc->content_length;
      return NGX_OK;
    }
    return cc->eof ? NGX_ERROR : NGX_AGAIN;
  }

  if (cc->eof) {
    cc->body.data = cc->body_start;
    cc->body.len = avail;
    return NGX_OK;
  }

  return NGX_AGAIN;
}


/* ------------------------------------------------------------------ */
/* the answer to the client                                            */
/* ------------------------------------------------------------------ */

static ngx_int_t waf_captcha_reply(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                                   ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc) {
  ngx_table_elt_t  *h;
  ngx_keyval_t     *kv;
  ngx_buf_t        *b;
  ngx_chain_t      out;
  ngx_uint_t       i;
  ngx_int_t        rc;
  u_char           *lowcase;

  rctx->waf_internal = 1;

  r->headers_out.status = cc->status;
  r->headers_out.content_length_n = cc->body.len;

  if (cc->content_type.len > 0) {
    r->headers_out.content_type = cc->content_type;
    r->headers_out.content_type_len = cc->content_type.len;
    r->headers_out.content_type_lowcase = NULL;
  }

  b = ngx_calloc_buf(r->pool);
  if (b == NULL) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                   STR_NOT_ALLOC_U_D, sizeof(ngx_buf_t), "cp6");
    return NGX_ERROR;
  }

  kv = cc->headers->elts;
  for (i = 0; i < cc->headers->nelts; i++) {

    lowcase = ngx_pnalloc(r->pool, kv[i].key.len);
    if (lowcase == NULL) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                     STR_NOT_ALLOC_U_D, kv[i].key.len, "cp14");
      return NGX_ERROR;
    }
    ngx_strlow(lowcase, kv[i].key.data, kv[i].key.len);

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                     STR_NOT_ALLOC_U_D, sizeof(ngx_table_elt_t), "cp15");
      return NGX_ERROR;
    }
    h->hash = 1;
    h->next = NULL;
    h->key = kv[i].key;
    h->value = kv[i].value;
    h->lowcase_key = lowcase;
  }

  if (!cc->origin_stored) {
    if (waf_captcha_set_cookie(rctx, r, cc) != NGX_OK) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                     STR_NOT_ALLOC_U_D, sizeof(ngx_table_elt_t), "cp16");
      return NGX_ERROR;
    }
  }

  rc = ngx_http_send_header(r);
  if ((rc == NGX_ERROR) || (rc > NGX_OK) || r->header_only) {
    return rc;
  }

  b->start = b->pos = cc->body.data;
  b->end = b->last = cc->body.data + cc->body.len;
  b->memory = 1;
  b->last_buf = 1;
  b->last_in_chain = 1;

  out.buf = b;
  out.next = NULL;

  ngx_http_output_filter(r, &out);
  ngx_http_finalize_request(r, NGX_DONE);

  return NGX_DONE;
}


static ngx_int_t waf_captcha_unban(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                                   ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc) {
  ngx_str_t    ip, mlc_s, uri, args;
  char         alloc_r;
  ngx_int_t    unban_rc;
  ngx_buf_t    *unban_buf;
  ngx_chain_t  unban_out;
  size_t       unban_len;

  ip = r->connection->addr_text;

  waf_delete_banned_ip(&ip, &shm_var, wmc);

  if (wmc->antibot_captcha_url != NULL) {
    set_ip_antibot_captcha(wmc, ip);
  }

  waf_log_error(WAF_LOG_INFO, WAF_CAT_MISC, wmc, NULL, NGX_LOG_INFO, r->connection->log, 0,
                 STR_CAPTCHA_UNBAN, &ip, &rctx->req_id_s);

  mlc_s.data = NULL;
  mlc_s.len = 0;
  waf_serial_data(r, wmc, &mlc_s, 1, waf_captcha_mlc_type, &ip);
  if (mlc_s.data != NULL) {
    rmq_send(wmc, "waf", &mlc_s);
    waf_pfree(mlc_s.data, &alloc_r, rctx->r_pool);
  }

  uri = cc->origin_uri;
  args = cc->origin_args;

  /*
   * The client gets the page it was heading to before the captcha: the
   * captcha step (a form POST as a rule) is turned into a plain GET of the
   * original URI which is then processed by the protected application.
   */
  waf_captcha_strip_cookie(r);

  r->method = NGX_HTTP_GET;
  r->method_name = waf_captcha_get_method;
  r->headers_in.content_length_n = 0;
  r->headers_in.chunked = 0;

  if (r->headers_in.content_length != NULL) {
    r->headers_in.content_length->hash = 0;
    r->headers_in.content_length = NULL;
  }
  if (r->headers_in.content_type != NULL) {
    r->headers_in.content_type->hash = 0;
    r->headers_in.content_type = NULL;
  }
  if (r->request_body != NULL) {
    r->request_body->bufs = NULL;
    r->request_body->buf = NULL;
    r->request_body->temp_file = NULL;
  }

  unban_buf = ngx_calloc_buf(r->pool);
  if (unban_buf == NULL){
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                  STR_NOT_ALLOC_U_D, sizeof(ngx_buf_t), "cp17");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  unban_out.buf = unban_buf;

  unban_out.next = NULL;

  r->headers_out.status = NGX_HTTP_OK;

  unban_len = (size_t)(sizeof(redirect_html) + uri.len);

  if (args.len > 0) {
    unban_len = unban_len + 1 + args.len;
  }

  unban_buf->start = ngx_pcalloc(r->pool, unban_len + 1);
  if (unban_buf->start == NULL){
    waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                  STR_NOT_ALLOC_U_D, (unban_len + 1), "cp18");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  unban_buf->pos = unban_buf->start;
  unban_buf->last = ngx_snprintf(unban_buf->start, unban_len, redirect_html, &uri, ((args.len > 0)?"?":""), &args);
  unban_buf->end = unban_buf->last;

  r->headers_out.content_length_n = (size_t)(unban_buf->last - unban_buf->start);
  r->headers_out.content_type_len = sizeof("text/html") - 1;
  ngx_str_set(&r->headers_out.content_type, "text/html");

  unban_rc = ngx_http_send_header(r);
  if ((unban_rc == NGX_ERROR) || (unban_rc > NGX_OK) || r->header_only){
    return unban_rc;
  }

   unban_buf->memory = 1;
   unban_buf->last_buf = 1;
   unban_buf->last_in_chain = 1;
   ngx_http_output_filter(r, &unban_out); 
   ngx_http_finalize_request(r, NGX_DONE);

   return NGX_DONE; 
}


/*
 * Reports a failed exchange. The client gets the response code of the captcha
 * server when it managed to answer, and 502 when it did not.
 */
static ngx_int_t waf_captcha_fail(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                                  ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc) {
  ngx_uint_t  code;

  code = NGX_HTTP_BAD_GATEWAY;
  if ((cc->status >= NGX_HTTP_BAD_REQUEST) && (cc->status <= WAF_CAPTCHA_LAST_STATUS)) {
    code = cc->status;
  }

  waf_log_error(WAF_LOG_ERR, WAF_CAT_NET, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                 STR_CAPTCHA_FAILED, &wmc->captcha_conf.host, &rctx->req_id_s, code);

  return (ngx_int_t) code;
}


static ngx_int_t waf_captcha_result(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                                    ngx_http_request_t *r, ngx_waf_captcha_ctx_t *cc) {
  ngx_int_t  rc;

  if (cc->pass == WAF_CAPTCHA_PASS_COMPLETE) {
    return waf_captcha_unban(wmc, rctx, r, cc);
  }

  if (cc->pass == WAF_CAPTCHA_PASS_PROGRESS) {
    return waf_captcha_reply(wmc, rctx, r, cc);
  }

  waf_log_error(WAF_LOG_ERR, WAF_CAT_MISC, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                 STR_CAPTCHA_BAD_RESPONSE, &rctx->req_id_s, cc->status);

  if (cc->retries >= WAF_CAPTCHA_MAX_RETRIES) {
    return NGX_ERROR;
  }

  /* show the captcha page again */
  cc->retries++;
  cc->page_only = 1;

  cc->sync = 1;
  rc = waf_captcha_start(wmc, rctx, r, cc);
  cc->sync = 0;

  if (rc != NGX_OK) {
    waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
    return NGX_ERROR;
  }

  return NGX_AGAIN;
}


/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

ngx_int_t waf_captcha_proxy(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                            ngx_http_request_t *r) {
  ngx_waf_captcha_ctx_t  *cc;
  ngx_http_cleanup_t     *cln;
  ngx_int_t              rc;

  if (!waf_captcha_ready(wmc)) {
    waf_log_error(WAF_LOG_ERR, WAF_CAT_SET, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                   STR_CONF_CAPTCHA_PARAM_M, "waf_ban_captcha_url", "waf_ban_captcha_host");
    return NGX_HTTP_BAD_GATEWAY;
  }

  cc = rctx->captcha;

  if (cc == NULL) {
    cc = ngx_pcalloc(r->pool, sizeof(ngx_waf_captcha_ctx_t));
    if (cc == NULL) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                     STR_NOT_ALLOC_U_D, sizeof(ngx_waf_captcha_ctx_t), "cp7");
      return NGX_ERROR;
    }

    cc->r = r;
    cc->content_length = -1;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
      waf_log_error(WAF_LOG_ERR, WAF_CAT_OS, wmc, NULL, NGX_LOG_ERR, r->connection->log, 0,
                     STR_NOT_ALLOC_U_D, sizeof(ngx_http_cleanup_t), "cp8");
      return NGX_ERROR;
    }
    cln->handler = waf_captcha_cleanup;
    cln->data = cc;

    rctx->captcha = cc;

    waf_captcha_locate_origin(r, cc);

    cc->sync = 1;
    rc = waf_captcha_start(wmc, rctx, r, cc);
    cc->sync = 0;

    if (rc != NGX_OK) {
      waf_captcha_done(cc, WAF_CAPTCHA_ST_FAILED);
    }
  }

  for ( ;; ) {

    if (cc->state == WAF_CAPTCHA_ST_FAILED) {
      waf_captcha_undelay(r);
      return waf_captcha_fail(wmc, rctx, r, cc);
    }

    if (cc->state != WAF_CAPTCHA_ST_READY) {
      r->read_event_handler = ngx_http_test_reading;
      r->write_event_handler = ngx_http_waf_req_delay;
      r->connection->write->delayed = 1;
      return NGX_AGAIN;
    }

    waf_captcha_undelay(r);

    rc = waf_captcha_result(wmc, rctx, r, cc);
    if (rc == NGX_AGAIN) {
      continue;
    }
    if (rc == NGX_ERROR) {
      return waf_captcha_fail(wmc, rctx, r, cc);
    }
    return rc;
  }
}
