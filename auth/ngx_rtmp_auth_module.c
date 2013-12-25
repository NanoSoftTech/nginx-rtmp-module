/*
 * Copyright (c) 2012 Neutron Soutmun
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_netcall_module.h>
#include <ngx_rtmp_streams.h>
#include "ngx_rtmp_auth_module.h"


#ifndef NGX_RTMP_FMS_VERSION
#define NGX_RTMP_FMS_VERSION     "FMS/3.0.1.123"
#endif
#ifndef NGX_RTMP_CAPABILITIES
#define NGX_RTMP_CAPABILITIES    31 
#endif


static ngx_rtmp_connect_pt  next_connect;
static ngx_str_t ngx_rtmp_auth_urlencoded =
        ngx_string("application/x-www-form-urlencoded");


static char *ngx_rtmp_auth_on_auth(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_auth_method(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_auth_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_auth_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_auth_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);


typedef struct {
    ngx_flag_t     auth;
    ngx_url_t     *auth_url;
    ngx_uint_t     method;
} ngx_rtmp_auth_app_conf_t;


static ngx_command_t  ngx_rtmp_auth_commands[] = {
    { ngx_string("auth"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_auth"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_auth_on_auth,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_method"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_auth_method,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },


      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_auth_module_ctx = {
    NULL,                                 /* preconfiguration */
    ngx_rtmp_auth_postconfiguration,      /* postconfiguration */
    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */
    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */
    ngx_rtmp_auth_create_app_conf,        /* create app configuration */
    ngx_rtmp_auth_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_auth_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_auth_module_ctx,            /* module context */
    ngx_rtmp_auth_commands,               /* module directives */
    NGX_RTMP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_auth_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_auth_app_conf_t    *aacf;

    aacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_auth_app_conf_t));
    if (aacf == NULL) {
        return NULL;
    }

    aacf->auth = NGX_CONF_UNSET;
    aacf->auth_url = NGX_CONF_UNSET_PTR;
    aacf->method = NGX_CONF_UNSET_UINT;

    return aacf;
}


static char *
ngx_rtmp_auth_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_auth_app_conf_t    *prev = parent;
    ngx_rtmp_auth_app_conf_t    *conf = child;

    ngx_conf_merge_value(conf->auth, prev->auth, 0);
    ngx_conf_merge_ptr_value(conf->auth_url, prev->auth_url, 0);
    ngx_conf_merge_uint_value(conf->method, prev->method,
                              NGX_RTMP_NETCALL_HTTP_POST);

    return NGX_CONF_OK;
}


static ngx_chain_t *
ngx_rtmp_auth_connect_create(ngx_rtmp_session_t *s, void *arg, ngx_pool_t *pool)
{
    ngx_rtmp_auth_app_conf_t    *aacf;
    ngx_chain_t                 *al, *bl, *cl, *pl;
    ngx_buf_t                   *b;

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auth_module);

    /* connect variables */
    pl = ngx_alloc_chain_link(pool);

    if (pl == NULL) {
        return NULL;
    }

    al = ngx_rtmp_netcall_http_format_session(s, pool);
    if (al == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool, sizeof("&call=auth") - 1);

    if (b == NULL) {
        return NULL;
    }

    pl->buf  = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char *) "&call=auth",
                         sizeof("&call=auth") - 1);

    al->next = pl;
    bl = NULL;

    if (aacf->method == NGX_RTMP_NETCALL_HTTP_POST) {
      cl = al;
      al = bl;
      bl = cl;
    }

    return ngx_rtmp_netcall_http_format_request(aacf->method,
                                                &aacf->auth_url->host,
                                                &aacf->auth_url->uri,
                                                al, bl, pool,
                                                &ngx_rtmp_auth_urlencoded);
}


static ngx_int_t
ngx_rtmp_auth_http_response_decode(ngx_rtmp_session_t *s,
    ngx_rtmp_auth_ctx_t *ctx)
{
    ngx_http_request_t    r;
    ngx_str_t             val;
    u_char                val_buf[NGX_RTMP_AUTH_MAX_RESPONSE];
    u_char                status;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "auth: response: %s", ctx->resp.data);

    val.len  = 0;
    val.data = val_buf;

    r.args.len  = ctx->resp.len;
    r.args.data = ctx->resp.data;

    ctx->conn_desc.len = 0;

    if (ngx_http_arg(&r, (u_char *) "desc", sizeof("desc") - 1, &val) == NGX_OK
            && val.len > 0) {

        ctx->conn_desc.len  = ngx_base64_decoded_length(val.len);
        ctx->conn_desc.data = ngx_pcalloc(s->connection->pool,
                                          ctx->conn_desc.len + 1);

        if (ctx->conn_desc.data != NULL &&
                ngx_decode_base64(&ctx->conn_desc, &val) == NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                           "auth: description: %s", ctx->conn_desc.data);
        } else {
          ctx->conn_desc.len = 0;
        }
    }

    val.len = 0;
    if (ngx_http_arg(&r, (u_char *) "status", sizeof ("status") - 1, &val)
            != NGX_OK || val.len == 0) {
        return NGX_ERROR;
    } else {
        status = val.data[0];

        ctx->user.len = 0;
        val.len       = 0;

        if (ngx_http_arg(&r, (u_char *) "user", sizeof("user") - 1, &val)
                == NGX_OK && val.len > 0) {
            ctx->user.data = ngx_pcalloc(s->connection->pool, val.len + 1);

            if (ctx->user.data != NULL) {
                u_char *dst = ctx->user.data;

                ngx_unescape_uri(&dst, &val.data, val.len, 0);
                *dst = '\0';

                ctx->user.len = ngx_strlen(ctx->user.data);
            }
        }

        ctx->authmod.len = 0;
        val.len = 0;

        if (ngx_http_arg(&r, (u_char *) "authmod", sizeof("authmod") - 1, &val)
                == NGX_OK && val.len > 0) {
            ctx->authmod.data = ngx_pcalloc(s->connection->pool, val.len + 1);

            if (ctx->authmod.data != NULL) {
                u_char *dst = ctx->authmod.data;

                ngx_unescape_uri(&dst, &val.data, val.len, 0);
                *dst = '\0';

                ctx->authmod.len = ngx_strlen(ctx->authmod.data);
            }
        }
    }

    switch (status) {
    /* Allow */
    case (u_char)'a':
    case (u_char)'A':
        if (ctx->user.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "auth: Allow, user: %s", ctx->user.data);
        } else {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "auth: Allow");
        }

        ctx->conn_status = NGX_RTMP_CONN_ALLOW;
        return NGX_OK;

    /* Reject */
    case (u_char)'r':
    case (u_char)'R':
        if (ctx->user.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "auth: Reject, user: %s", ctx->user.data);
        } else {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "auth: Reject");
        }

        if (ctx->conn_desc.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "auth: Reject, reason: %s", ctx->conn_desc.data);
        }

        ctx->conn_status = NGX_RTMP_CONN_REJECT;
        return NGX_OK;

    /* Deny */
    case (u_char)'d':
    case (u_char)'D':
    default:
        if (ctx->user.len > 0) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "auth: Deny, user: %s", ctx->user.data);
        } else {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "auth: Deny");
        }

        ctx->conn_status = NGX_RTMP_CONN_DENY;
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_rtmp_auth_parse_http_response(ngx_rtmp_session_t *s, ngx_chain_t *in,
    ngx_rtmp_auth_ctx_t *ctx)
{
    ngx_buf_t    *b;
    size_t        chunk;
    size_t        len;

    ctx->conn_status = NGX_RTMP_CONN_DENY;

    enum {
        sw_header = 0,
        sw_cr,
        sw_crlf,
        sw_crlfcr,
        sw_lf,
        sw_response
    } state;

    state = 0;

    while (in) {
        u_char    *p = NULL;

        b = in->buf;
        for (p = b->pos; p < b->last; p++) {
            u_char    ch = *p;

            switch (state) {
            case sw_header:
                switch (ch) {
                    case CR:
                      state = sw_cr;
                      break;
                    case LF:
                      state = sw_lf;
                      break;
                }
                break;

            case sw_cr:
                state = ch == LF ? sw_crlf : sw_header;
                break;

            case sw_crlf:
                state = ch == CR ? sw_crlfcr : sw_header;
                break;

            case sw_crlfcr:
            case sw_lf:
                state = ch == LF ? sw_response : sw_header;
                break;

            case sw_response:
                chunk = b->last - p;
                len = chunk;

                if (ctx->resp.len + len >= NGX_RTMP_AUTH_MAX_RESPONSE) {
                    len = NGX_RTMP_AUTH_MAX_RESPONSE - ctx->resp.len - 1;
                }

                ngx_memcpy(ctx->resp.data, p, len);
                ctx->resp.len += len;

                if (len != chunk) {
                    ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                                  "auth: response is truncated, "
                                  "incompleted response may fail "
                                  "the authtication");
                    goto done;
                }

                p += len;
                break;
            }
        }

        in = in->next;
    }

done:
    ctx->resp.data[ctx->resp.len] = '\0';
    if (ctx->resp.data[0] != '\0') {
        return ngx_rtmp_auth_http_response_decode (s, ctx);
    } else {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "auth: Deny");
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_rtmp_auth_parse_http_retcode(ngx_rtmp_session_t *s, ngx_chain_t *in,
    ngx_rtmp_auth_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_int_t     n;
    u_char        c;

    /* find 10th character */
    n = 9;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            c = b->pos[n];
            if (c >= (u_char)'0' && c <= (u_char)'9') {
                ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                               "auth: HTTP retcode: %cxx", c);

                if (c == (u_char)'2')
                    return NGX_OK;
                else
                    return NGX_ERROR;
            }

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "auth: invalid HTTP retcode: %d..", (int)c);

            return NGX_ERROR;
        }

        n -= (b->last - b->pos);
        in = in->next;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_auth_connect_reject(ngx_rtmp_session_t *s, 
    ngx_rtmp_connect_t *v, ngx_rtmp_auth_ctx_t *ctx)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t  **cacfp;
    ngx_uint_t                  n;
    ngx_rtmp_header_t           h;
    u_char                     *p;

    static double               trans;
    static double               capabilities = NGX_RTMP_CAPABILITIES;
    static double               object_encoding = 0;

    static ngx_rtmp_amf_elt_t  out_obj[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("fmsVer"),
          NGX_RTMP_FMS_VERSION, 0 },
        
        { NGX_RTMP_AMF_NUMBER,
          ngx_string("capabilities"),
          &capabilities, 0 },
    };

    static ngx_rtmp_amf_elt_t  out_inf[] = {

        { NGX_RTMP_AMF_STRING, 
          ngx_string("level"),
          "error", 0 },

        { NGX_RTMP_AMF_STRING, 
          ngx_string("code"),
          "NetConnection.Connect.Rejected", 0 }, 

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("objectEncoding"),
          &object_encoding, 0 }
    };

    out_inf[2].data = ctx->conn_desc.len > 0 ? (void *) ctx->conn_desc.data :
                          "[ AccessManager.Reject ]";

    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,       
          "_result", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_obj, sizeof(out_obj) },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    if (s->connected) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                "auth: duplicate connection");
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    trans = v->trans;

    /* fill session parameters */
    s->connected = 1;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    p = ngx_strlchr(s->app.data, s->app.data + s->app.len, '?');
    if (p) {
        s->app.len = (p - s->app.data);
    }

    s->acodecs = (uint32_t) v->acodecs;
    s->vcodecs = (uint32_t) v->vcodecs;

    /* find application & set app_conf */
    cacfp = cscf->applications.elts;
    for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == s->app.len &&
            ngx_strncmp((*cacfp)->name.data, s->app.data, s->app.len) == 0)
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, 
                      "auth: application not found: '%V'", &s->app);
        return NGX_ERROR;
    }

    object_encoding = v->object_encoding;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "auth: reject - %s",
                   ctx->conn_desc.len > 0 ? (void *) ctx->conn_desc.data :
                       "no reason");

    return ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK ||
           ngx_rtmp_send_bandwidth(s, cscf->ack_window, 
                                   NGX_RTMP_LIMIT_DYNAMIC) != NGX_OK ||
           ngx_rtmp_send_chunk_size(s, cscf->chunk_size) != NGX_OK ||
           ngx_rtmp_send_amf(s, &h, out_elts,
                             sizeof(out_elts) / sizeof(out_elts[0]))
           != NGX_OK ? NGX_ERROR : NGX_ERROR; 
}


static ngx_int_t
ngx_rtmp_auth_connect_handle(ngx_rtmp_session_t *s, void *arg, ngx_chain_t *in)
{
    ngx_rtmp_connect_t     *v = (ngx_rtmp_connect_t *) arg;
    ngx_rtmp_auth_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auth_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_auth_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_auth_module);

        ctx->resp.len  = 0;
        ctx->resp.data = ctx->resp_data;
    }

    if (ngx_rtmp_auth_parse_http_retcode(s, in, ctx) != NGX_OK)
        return NGX_ERROR;

    if (ngx_rtmp_auth_parse_http_response(s, in, ctx) != NGX_OK)
        return NGX_ERROR;

    if (ctx->conn_status == NGX_RTMP_CONN_ALLOW) {
      return next_connect(s, v);
    } else {
      return ngx_rtmp_auth_connect_reject(s, v, ctx);
    }
}


static ngx_int_t
ngx_rtmp_auth_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_core_srv_conf_t     *cscf;
    ngx_rtmp_core_app_conf_t    **cacfp;
    ngx_rtmp_auth_app_conf_t     *aacf;
    ngx_rtmp_netcall_init_t       ci;
    ngx_uint_t                    n;
    size_t                        len;
    char                         *p;

    if (s->connected) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "auth: duplicate connection");
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    p = ngx_strchr (v->app, '?');
    if (p) {
        *p = 0;
    }

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "auth: app='%s' flashver='%s' swf_url='%s' "
                   "tc_url='%s' page_url='%s' acodecs=%uD vcodecs=%uD "
                   "object_encoding=%ui",
                   v->app, v->flashver, v->swf_url, v->tc_url, v->page_url,
                   (uint32_t) v->acodecs, (uint32_t) v->vcodecs,
                   (ngx_int_t) v->object_encoding);

#define NGX_RTMP_SET_STRPAR(name)                                             \
    s->name.len  = ngx_strlen(v->name);                                        \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);              \
    ngx_memcpy(s->name.data, v->name, s->name.len)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

#undef NGX_RTMP_SET_STRPAR

    s->acodecs = v->acodecs;
    s->vcodecs = v->vcodecs;

    /* find application & set app_conf */
    len = ngx_strlen(v->app);

    cacfp = cscf->applications.elts;
    for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == len
                && !ngx_strncmp((*cacfp)->name.data, v->app, len))
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "auth: application not found: '%s'", v->app);
        return NGX_ERROR;
    }

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auth_module);
    if (aacf == NULL || !aacf->auth || aacf->auth_url == NULL ||
        aacf->auth_url->uri.len == 0) {
        goto next;
    }

    ngx_memzero(&ci, sizeof(ci));
    ci.url     = aacf->auth_url;
    ci.create  = ngx_rtmp_auth_connect_create;
    ci.handle  = ngx_rtmp_auth_connect_handle;
    ci.arg     = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci) == NGX_OK ? NGX_AGAIN : NGX_ERROR;

next:
    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "auth: bypassed");
    return next_connect(s, v);
}


static char *
ngx_rtmp_auth_on_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_auth_app_conf_t    *aacf;
    ngx_str_t                   *url;
    ngx_url_t                   *u;
    size_t                       add;
    ngx_str_t                   *value;

    value = cf->args->elts;
    url   = &value[1];
    add   = 0;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    u->url.len  = url->len - add;
    u->url.data = url->data + add;
    u->default_port = 80;
    u->uri_part = 1;

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in url \"%V\"",
                               u->err, &u->url);
        }
        return NGX_CONF_ERROR;
    }

    aacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_auth_module);
    aacf->auth_url = u;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_auth_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_auth_app_conf_t     *aacf = conf;

    ngx_str_t                      *value;

    value = cf->args->elts;
    value++;

    if (value->len == sizeof("get") - 1 &&
        ngx_strncasecmp(value->data, (u_char *) "get", value->len) == 0)
    {
        aacf->method = NGX_RTMP_NETCALL_HTTP_GET;

    } else if (value->len == sizeof("post") - 1 &&
               ngx_strncasecmp(value->data, (u_char *) "post", value->len) == 0)
    {
        aacf->method = NGX_RTMP_NETCALL_HTTP_POST;

    } else {
        return "got unexpected method";
    }

    return NGX_CONF_OK;
}




static ngx_int_t
ngx_rtmp_auth_postconfiguration(ngx_conf_t *cf)
{
    next_connect     = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_auth_connect;

    return NGX_OK;
}
