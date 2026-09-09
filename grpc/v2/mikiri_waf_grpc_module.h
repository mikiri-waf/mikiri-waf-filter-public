#ifndef WAF_GRPC_MOD_H
#define WAF_GRPC_MOD_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t               *flushes;
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_hash_t                 hash;
} ngx_http_grpc_headers_t;


typedef struct {
    ngx_http_upstream_conf_t   upstream;

    ngx_http_grpc_headers_t    headers;
    ngx_array_t               *headers_source;

    ngx_str_t                  host;
    ngx_uint_t                 host_set;

    ngx_array_t               *grpc_lengths;
    ngx_array_t               *grpc_values;

#if (NGX_HTTP_SSL)
    ngx_uint_t                 ssl;
    ngx_uint_t                 ssl_protocols;
    ngx_str_t                  ssl_ciphers;
    ngx_uint_t                 ssl_verify_depth;
    ngx_str_t                  ssl_trusted_certificate;
    ngx_str_t                  ssl_crl;
    ngx_array_t               *ssl_conf_commands;
#endif
} ngx_http_grpc_loc_conf_t;


typedef enum {
    ngx_http_grpc_st_start = 0,
    ngx_http_grpc_st_length_2,
    ngx_http_grpc_st_length_3,
    ngx_http_grpc_st_type,
    ngx_http_grpc_st_flags,
    ngx_http_grpc_st_stream_id,
    ngx_http_grpc_st_stream_id_2,
    ngx_http_grpc_st_stream_id_3,
    ngx_http_grpc_st_stream_id_4,
    ngx_http_grpc_st_payload,
    ngx_http_grpc_st_padding
} ngx_http_grpc_state_e;


typedef struct {
    size_t                     init_window;
    size_t                     send_window;
    size_t                     recv_window;
    ngx_uint_t                 last_stream_id;
} ngx_http_grpc_conn_t;


typedef struct {
    ngx_http_grpc_state_e      state;
    ngx_uint_t                 frame_state;
    ngx_uint_t                 fragment_state;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t               *free;
    ngx_chain_t               *busy;

    ngx_http_grpc_conn_t      *connection;

    ngx_uint_t                 id;

    ngx_uint_t                 pings;
    ngx_uint_t                 settings;

    off_t                      length;

    ssize_t                    send_window;
    size_t                     recv_window;

    size_t                     rest;
    ngx_uint_t                 stream_id;
    u_char                     type;
    u_char                     flags;
    u_char                     padding;

    ngx_uint_t                 error;
    ngx_uint_t                 window_update;

    ngx_uint_t                 setting_id;
    ngx_uint_t                 setting_value;

    u_char                     ping_data[8];

    ngx_uint_t                 index;
    ngx_str_t                  name;
    ngx_str_t                  value;

    u_char                    *field_end;
    size_t                     field_length;
    size_t                     field_rest;
    u_char                     field_state;

    unsigned                   literal:1;
    unsigned                   field_huffman:1;

    unsigned                   header_sent:1;
    unsigned                   output_closed:1;
    unsigned                   output_blocked:1;
    unsigned                   parsing_headers:1;
    unsigned                   end_stream:1;
    unsigned                   done:1;
    unsigned                   status:1;
    unsigned                   rst:1;
    unsigned                   goaway:1;

    ngx_http_request_t        *request;

    ngx_str_t                  host;
} ngx_http_grpc_ctx_t;

typedef struct {
    ngx_chain_t               *in;
    unsigned                   header_sent:1;
    unsigned                   external_handlers:1;
    unsigned                   data_parsed:1;
    unsigned                   filter_delayed:1;
    ngx_http_request_t        *request;
} ngx_http_waf_grpc_ctx_t;

typedef struct {
    u_char                     length_0;
    u_char                     length_1;
    u_char                     length_2;
    u_char                     type;
    u_char                     flags;
    u_char                     stream_id_0;
    u_char                     stream_id_1;
    u_char                     stream_id_2;
    u_char                     stream_id_3;
} ngx_http_grpc_frame_t;

void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);
void ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
void ngx_http_upstream_block_reading(ngx_http_request_t *r, ngx_http_upstream_t *u);

#endif
