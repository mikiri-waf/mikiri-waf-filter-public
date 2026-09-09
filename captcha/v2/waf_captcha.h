#ifndef WAF_CAPTCHA_H
#define WAF_CAPTCHA_H

#include "mikiri_waf_http_module.h"

/* states of the captcha exchange kept in rctx->captcha */
#define WAF_CAPTCHA_ST_CONNECT    1   // waiting for the TCP connection
#define WAF_CAPTCHA_ST_HANDSHAKE  2   // waiting for the TLS handshake
#define WAF_CAPTCHA_ST_SEND       3   // sending the request
#define WAF_CAPTCHA_ST_READ       4   // reading the response
#define WAF_CAPTCHA_ST_READY      5   // response received, ready to be processed
#define WAF_CAPTCHA_ST_FAILED     6   // exchange failed

/* value of the x-waf-captcha-challenge response header */
#define WAF_CAPTCHA_PASS_NONE     0
#define WAF_CAPTCHA_PASS_PROGRESS 1
#define WAF_CAPTCHA_PASS_COMPLETE 2

struct ngx_waf_captcha_ctx_s {
  ngx_http_request_t    *r;
  ngx_peer_connection_t peer;

  ngx_uint_t            state;
  ngx_uint_t            retries;         // captcha page re-requests after an incorrect response
  ngx_flag_t            page_only;       // request the captcha page instead of proxying the client request
  ngx_flag_t            finished;        // the exchange is over, the request is resumed only once
  ngx_flag_t            sync;            // the exchange is driven from the request handler

  ngx_buf_t             out;             // request to the captcha server
  ngx_buf_t             in;              // raw response from the captcha server
  ngx_flag_t            eof;

  ngx_flag_t            headers_parsed;
  u_char                *body_start;     // first byte of the response body inside "in"
  ngx_int_t             content_length;  // -1 if the response has no Content-Length
  ngx_flag_t            chunked;

  ngx_uint_t            status;          // response status code
  ngx_array_t           *headers;        // ngx_keyval_t, response headers to relay to the client
  ngx_str_t             content_type;
  ngx_str_t             body;
  ngx_uint_t            pass;            // WAF_CAPTCHA_PASS_*

  ngx_str_t             origin;          // "uri[?args]" of the page the client was heading to
  ngx_str_t             origin_uri;
  ngx_str_t             origin_args;
  ngx_flag_t            origin_stored;   // origin was taken from the client cookie
};

ngx_int_t waf_captcha_parse_url(ngx_cycle_t *cycle, ngx_http_waf_main_conf_t *wmc);
ngx_flag_t waf_captcha_ready(ngx_http_waf_main_conf_t *wmc);
ngx_int_t waf_captcha_proxy(ngx_http_waf_main_conf_t *wmc, ngx_http_request_ctx_t *rctx,
                            ngx_http_request_t *r);

#endif
