/*
 * NAPI surface for the tunnel engine.
 *
 * Deliberately tiny: ArkTS passes configuration in, and reads counters out.
 * No packet and no callback crosses this boundary, which is the whole point of
 * moving the data path into C.
 */
#include <node_api.h>

#include <cstdio>
#include <cstring>

#include "wg/tunnel.h"

#if defined(__OHOS__)
#include <hilog/log.h>
#define WG_LOG_DOMAIN 0xD001
#define WG_LOG_TAG "WgTunnel"
#endif

/* ── logging ── */

static void LogSink(int level, const char *msg) {
#if defined(__OHOS__)
    LogLevel prio = LOG_INFO;
    if (level <= 0) prio = LOG_ERROR;
    else if (level == 1) prio = LOG_WARN;
    else if (level >= 3) prio = LOG_DEBUG;
    OH_LOG_Print(LOG_APP, prio, WG_LOG_DOMAIN, WG_LOG_TAG, "%{public}s", msg);
#else
    printf("[wg %d] %s\n", level, msg);
#endif
}

/* ── helpers ── */

static bool GetInt32(napi_env env, napi_value obj, const char *name, int32_t *out) {
    napi_value v;
    if (napi_get_named_property(env, obj, name, &v) != napi_ok) return false;
    napi_valuetype t;
    if (napi_typeof(env, v, &t) != napi_ok || t != napi_number) return false;
    return napi_get_value_int32(env, v, out) == napi_ok;
}

static bool GetString(napi_env env, napi_value obj, const char *name,
                      char *buf, size_t cap) {
    napi_value v;
    size_t len = 0;
    if (napi_get_named_property(env, obj, name, &v) != napi_ok) return false;
    napi_valuetype t;
    if (napi_typeof(env, v, &t) != napi_ok || t != napi_string) return false;
    if (napi_get_value_string_utf8(env, v, buf, cap, &len) != napi_ok) return false;
    return len > 0 && len < cap;
}

/* Copies a Uint8Array of at least `need` bytes; zeros the target when absent. */
static bool GetBytes(napi_env env, napi_value obj, const char *name,
                     uint8_t *out, size_t need, bool required) {
    napi_value v;
    napi_typedarray_type type;
    size_t length = 0;
    void *data = nullptr;
    napi_value ab;
    size_t offset = 0;

    memset(out, 0, need);

    if (napi_get_named_property(env, obj, name, &v) != napi_ok) return !required;
    napi_valuetype t;
    if (napi_typeof(env, v, &t) != napi_ok) return !required;
    if (t == napi_undefined || t == napi_null) return !required;

    if (napi_get_typedarray_info(env, v, &type, &length, &data, &ab, &offset) != napi_ok) {
        return false;
    }
    if (type != napi_uint8_array || length < need) return false;
    memcpy(out, data, need);
    return true;
}

static bool ParseIPv4(const char *text, uint8_t out[4]) {
    unsigned a, b, c, d;
    if (!text || sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b;
    out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return true;
}

/* ── exported functions ── */

static napi_value Start(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_value result;
    wg_tunnel_config cfg;
    char server_ip[64];
    char client_ip[32];
    int32_t tun_fd = -1, port = 0, mtu = 1420;
    int rc;

    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc < 1) {
        napi_create_int32(env, -22, &result);
        return result;
    }

    napi_valuetype t;
    if (napi_typeof(env, argv[0], &t) != napi_ok || t != napi_object) {
        napi_create_int32(env, -22, &result);
        return result;
    }

    memset(&cfg, 0, sizeof(cfg));

    if (!GetInt32(env, argv[0], "tunFd", &tun_fd)) {
        napi_create_int32(env, -22, &result);
        return result;
    }
    if (!GetString(env, argv[0], "serverIp", server_ip, sizeof(server_ip))) {
        napi_create_int32(env, -22, &result);
        return result;
    }
    if (!GetInt32(env, argv[0], "serverPort", &port) || port <= 0 || port > 65535) {
        napi_create_int32(env, -22, &result);
        return result;
    }
    if (!GetBytes(env, argv[0], "clientPriv", cfg.client_priv, 32, true)) {
        napi_create_int32(env, -22, &result);
        return result;
    }
    if (!GetBytes(env, argv[0], "serverPub", cfg.server_pub, 32, true)) {
        napi_create_int32(env, -22, &result);
        return result;
    }
    /* psk is optional: absent means "no preshared key", i.e. 32 zero bytes */
    GetBytes(env, argv[0], "psk", cfg.psk, 32, false);

    if (!GetString(env, argv[0], "clientIp", client_ip, sizeof(client_ip)) ||
        !ParseIPv4(client_ip, cfg.client_ip)) {
        napi_create_int32(env, -22, &result);
        return result;
    }

    if (GetInt32(env, argv[0], "mtu", &mtu)) cfg.mtu = mtu;

    cfg.tun_fd = (intptr_t)tun_fd;
    cfg.server_ip = server_ip;
    cfg.server_port = port;

    wg_tunnel_set_log(LogSink);
    rc = wg_tunnel_start(&cfg);

    napi_create_int32(env, rc, &result);
    return result;
}

static napi_value Stop(napi_env env, napi_callback_info info) {
    napi_value result;
    (void)info;
    wg_tunnel_stop();
    napi_get_undefined(env, &result);
    return result;
}

static napi_value IsRunning(napi_env env, napi_callback_info info) {
    napi_value result;
    (void)info;
    napi_get_boolean(env, wg_tunnel_is_running() != 0, &result);
    return result;
}

static void SetNum(napi_env env, napi_value obj, const char *name, double v) {
    napi_value n;
    napi_create_double(env, v, &n);
    napi_set_named_property(env, obj, name, n);
}

static void SetBool(napi_env env, napi_value obj, const char *name, bool v) {
    napi_value n;
    napi_get_boolean(env, v, &n);
    napi_set_named_property(env, obj, name, n);
}

static napi_value GetStats(napi_env env, napi_callback_info info) {
    wg_tunnel_stats st;
    napi_value obj;
    (void)info;

    wg_tunnel_get_stats(&st);

    napi_create_object(env, &obj);
    SetNum(env, obj, "txPackets", (double)st.tx_packets);
    SetNum(env, obj, "txBytes", (double)st.tx_bytes);
    SetNum(env, obj, "rxPackets", (double)st.rx_packets);
    SetNum(env, obj, "rxBytes", (double)st.rx_bytes);
    SetNum(env, obj, "txDrops", (double)st.tx_drops);
    SetNum(env, obj, "rxDrops", (double)st.rx_drops);
    SetNum(env, obj, "decryptErrors", (double)st.decrypt_errors);
    SetNum(env, obj, "handshakes", (double)st.handshakes);
    SetNum(env, obj, "handshakeFailures", (double)st.handshake_failures);
    SetNum(env, obj, "rekeys", (double)st.rekeys);
    SetNum(env, obj, "uptimeMs", (double)st.uptime_ms);
    SetNum(env, obj, "lastHandshakeAgeMs", (double)st.last_handshake_age_ms);
    SetNum(env, obj, "localIndex", (double)st.local_index);
    SetNum(env, obj, "remoteIndex", (double)st.remote_index);
    SetBool(env, obj, "connected", st.connected != 0);
    SetBool(env, obj, "running", wg_tunnel_is_running() != 0);
    return obj;
}

/* ── module registration ── */

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        { "start",     nullptr, Start,     nullptr, nullptr, nullptr, napi_default, nullptr },
        { "stop",      nullptr, Stop,      nullptr, nullptr, nullptr, napi_default, nullptr },
        { "getStats",  nullptr, GetStats,  nullptr, nullptr, nullptr, napi_default, nullptr },
        { "isRunning", nullptr, IsRunning, nullptr, nullptr, nullptr, napi_default, nullptr },
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

static napi_module wgTunnelModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "wg_tunnel",
    .nm_priv = nullptr,
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterWgTunnelModule(void) {
    napi_module_register(&wgTunnelModule);
}
