#ifndef WAF_WS_MOD_H
#define WAF_WS_MOD_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>

#define  NGX_HTTP_PROXY_COOKIE_SECURE           0x0001
#define  NGX_HTTP_PROXY_COOKIE_SECURE_ON        0x0002
#define  NGX_HTTP_PROXY_COOKIE_SECURE_OFF       0x0004
#define  NGX_HTTP_PROXY_COOKIE_HTTPONLY         0x0008
#define  NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON      0x0010
#define  NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF     0x0020
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE         0x0040
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT  0x0080
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX     0x0100
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE    0x0200
#define  NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF     0x0400

typedef struct ngx_http_proxy_rewrite_s  ngx_http_proxy_rewrite_t;

typedef ngx_int_t (*ngx_http_proxy_rewrite_pt)(ngx_http_request_t *r,
    ngx_str_t *value, size_t prefix, size_t len,
    ngx_http_proxy_rewrite_t *pr);

struct ngx_http_proxy_rewrite_s {
    ngx_http_proxy_rewrite_pt      handler;

    union {
        ngx_http_complex_value_t   complex;
#if (NGX_PCRE)
        ngx_http_regex_t          *regex;
#endif
    } pattern;

    ngx_http_complex_value_t       replacement;
};

typedef struct {
    union {
        ngx_http_complex_value_t   complex;
#if (NGX_PCRE)
        ngx_http_regex_t          *regex;
#endif
    } cookie;

    ngx_array_t                    flags_values;
    ngx_uint_t                     regex;
} ngx_http_proxy_cookie_flags_t;

typedef struct ngx_http_header_val_s  ngx_http_header_val_t;

typedef ngx_int_t (*ngx_http_set_header_pt)(ngx_http_request_t *r,
  ngx_http_header_val_t *hv, ngx_str_t *value);

struct ngx_http_header_val_s {
  ngx_http_complex_value_t   value;
  ngx_str_t                  key;
  ngx_http_set_header_pt     handler;
  ngx_uint_t                 offset;
  ngx_uint_t                 always;  /* unsigned  always:1 */
};

typedef enum {
  NGX_HTTP_EXPIRES_OFF,
  NGX_HTTP_EXPIRES_EPOCH,
  NGX_HTTP_EXPIRES_MAX,
  NGX_HTTP_EXPIRES_ACCESS,
  NGX_HTTP_EXPIRES_MODIFIED,
  NGX_HTTP_EXPIRES_DAILY,
  NGX_HTTP_EXPIRES_UNSET
} ngx_http_expires_t;

typedef struct {
  ngx_http_expires_t         expires;
  time_t                     expires_time;
  ngx_http_complex_value_t  *expires_value;
  ngx_array_t               *headers;
  ngx_array_t               *trailers;
} ngx_http_headers_conf_t;

void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);

#endif