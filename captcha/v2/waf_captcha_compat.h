/*
 * Mikiri WAF CAPTCHA - nginx compatibility layer
 * Copyright (c) Mikiri Security, LLC
 *
 * This is the only file of the addon that differs between the version
 * directories, waf_captcha.c and waf_captcha.h are the same everywhere.
 *
 * Variant for nginx 1.29.8 and newer: cookies are read with the dedicated
 * ngx_http_parse_cookie_lines(), which splits the header value by ";".
 */

#ifndef WAF_CAPTCHA_COMPAT_H
#define WAF_CAPTCHA_COMPAT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_inline ngx_table_elt_t *
waf_captcha_find_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value)
{
    if (r->headers_in.cookie == NULL) {
        return NULL;
    }

    return ngx_http_parse_cookie_lines(r, r->headers_in.cookie, name, value);
}

#endif
