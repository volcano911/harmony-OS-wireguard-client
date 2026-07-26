/**
 * Native UDP Socket for WireGuard VPN (HarmonyOS NAPI)
 *
 * 提供原生 UDP socket，及后台收包线程（pthread），
 * 通过 NAPI threadsafe callback 将数据回调到 ArkTS。
 */

#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <pthread.h>
#include <atomic>
#include <vector>

#include "napi/native_api.h"

// ── 辅助 ──

static std::string GetString(napi_env env, napi_value val) {
    size_t len = 0;
    napi_get_value_string_utf8(env, val, nullptr, 0, &len);
    if (len == 0) return "";
    std::string s(len, '\0');
    napi_get_value_string_utf8(env, val, &s[0], len + 1, &len);
    return s;
}

// ── 后台收包线程 ──

struct RecvData {
    uint64_t rxBytes;
    uint64_t rxPackets;
    uint64_t txBytes;
    uint64_t txPackets;
    size_t lastPacketLen;
    int direction;
};

struct RecvThreadCtx {
    int fd;
    int forwardFd;
    int relayFd;
    int forwardPort;
    struct sockaddr_in remoteAddr;
    pthread_t thread;
    std::atomic<bool> running;
    std::atomic<uint64_t> rxBytes;
    std::atomic<uint64_t> rxPackets;
    std::atomic<uint64_t> txBytes;
    std::atomic<uint64_t> txPackets;
    napi_threadsafe_function tsfn;
};

static RecvThreadCtx g_ctx;
static pthread_mutex_t g_ctxMutex = PTHREAD_MUTEX_INITIALIZER;

// ── TUN 专用读取线程 ──

struct TunReadEvent {
    std::vector<uint8_t> packet;
    int event;
    int fdFlags;
    int revents;
    int errorNo;
    uint64_t pollCount;
};

struct TunReadThreadCtx {
    int fd = -1;
    pthread_t thread {};
    std::atomic<bool> running {false};
    bool threadStarted = false;
    napi_threadsafe_function tsfn = nullptr;
};

static TunReadThreadCtx g_tunCtx;
static pthread_mutex_t g_tunMutex = PTHREAD_MUTEX_INITIALIZER;

static void TunReadTSFNCallback(
    napi_env env, napi_value jsCallback, void* context, void* data) {
    TunReadEvent* event = static_cast<TunReadEvent*>(data);
    if (event == nullptr) return;
    if (env == nullptr || jsCallback == nullptr) {
        delete event;
        return;
    }

    napi_value args[6];
    if (event->packet.empty()) {
        napi_get_null(env, &args[0]);
    } else {
        void* output = nullptr;
        napi_create_arraybuffer(env, event->packet.size(), &output, &args[0]);
        memcpy(output, event->packet.data(), event->packet.size());
    }
    napi_create_int32(env, event->event, &args[1]);
    napi_create_int32(env, event->fdFlags, &args[2]);
    napi_create_int32(env, event->revents, &args[3]);
    napi_create_int32(env, event->errorNo, &args[4]);
    napi_create_double(env, static_cast<double>(event->pollCount), &args[5]);
    napi_call_function(env, nullptr, jsCallback, 6, args, nullptr);
    delete event;
}

static bool QueueTunReadEvent(
    TunReadThreadCtx* ctx, int event, const uint8_t* packet, size_t length,
    int fdFlags, int revents, int errorNo, uint64_t pollCount) {
    TunReadEvent* data = new TunReadEvent();
    data->event = event;
    data->fdFlags = fdFlags;
    data->revents = revents;
    data->errorNo = errorNo;
    data->pollCount = pollCount;
    if (packet != nullptr && length > 0) {
        data->packet.assign(packet, packet + length);
    }

    napi_status status = napi_call_threadsafe_function(
        ctx->tsfn, data, napi_tsfn_nonblocking);
    if (status == napi_queue_full) {
        delete data;
        return true;
    }
    if (status != napi_ok) {
        delete data;
        return false;
    }
    return true;
}

static void* TunReadThreadMain(void* arg) {
    TunReadThreadCtx* ctx = static_cast<TunReadThreadCtx*>(arg);
    const int fdFlags = fcntl(ctx->fd, F_GETFL, 0);
    uint64_t pollCount = 0;
    uint64_t timeoutCount = 0;
    uint64_t eagainCount = 0;
    QueueTunReadEvent(ctx, 0, nullptr, 0, fdFlags, 0, 0, pollCount);

    uint8_t buffer[65536];
    while (ctx->running.load()) {
        struct pollfd pfd {};
        pfd.fd = ctx->fd;
        pfd.events = POLLIN;
        const int pollResult = poll(&pfd, 1, 250);
        pollCount++;

        if (!ctx->running.load()) break;
        if (pollResult == 0) {
            timeoutCount++;
            if (timeoutCount == 1 || timeoutCount % 40 == 0) {
                if (!QueueTunReadEvent(
                    ctx, 2, nullptr, 0, fdFlags, 0, 0, pollCount)) {
                    break;
                }
            }
            continue;
        }
        if (pollResult < 0) {
            if (errno == EINTR) continue;
            const int savedErrno = errno;
            QueueTunReadEvent(
                ctx, 3, nullptr, 0, fdFlags, 0, savedErrno, pollCount);
            break;
        }

        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            QueueTunReadEvent(
                ctx, 3, nullptr, 0, fdFlags, pfd.revents, 0, pollCount);
            if ((pfd.revents & POLLNVAL) != 0) break;
        }
        if ((pfd.revents & POLLIN) == 0) continue;

        bool readPacket = false;
        while (ctx->running.load()) {
            ssize_t bytesRead;
            do {
                bytesRead = read(ctx->fd, buffer, sizeof(buffer));
            } while (bytesRead < 0 && errno == EINTR);

            if (bytesRead > 0) {
                readPacket = true;
                if (!QueueTunReadEvent(
                    ctx, 1, buffer, static_cast<size_t>(bytesRead),
                    fdFlags, pfd.revents, 0, pollCount)) {
                    ctx->running.store(false);
                    break;
                }
                continue;
            }
            if (bytesRead == 0) {
                QueueTunReadEvent(
                    ctx, 5, nullptr, 0, fdFlags, pfd.revents, 0, pollCount);
                ctx->running.store(false);
                break;
            }

            const int savedErrno = errno;
            if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                if (!readPacket) {
                    eagainCount++;
                    if (eagainCount <= 10 || eagainCount % 100 == 0) {
                        QueueTunReadEvent(
                            ctx, 4, nullptr, 0, fdFlags, pfd.revents,
                            savedErrno, pollCount);
                    }
                }
                break;
            }
            QueueTunReadEvent(
                ctx, 3, nullptr, 0, fdFlags, pfd.revents,
                savedErrno, pollCount);
            ctx->running.store(false);
            break;
        }
    }

    napi_release_threadsafe_function(ctx->tsfn, napi_tsfn_release);
    return nullptr;
}

static void StopTunReadThreadInternal() {
    g_tunCtx.running.store(false);
    if (g_tunCtx.threadStarted) {
        pthread_join(g_tunCtx.thread, nullptr);
        g_tunCtx.threadStarted = false;
    }
    g_tunCtx.fd = -1;
    g_tunCtx.tsfn = nullptr;
}

static napi_value StartTunReadThread(
    napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 2) {
        napi_throw_error(env, nullptr, "expected 2 args (fd, callback)");
        return nullptr;
    }

    int fd = -1;
    napi_get_value_int32(env, args[0], &fd);
    if (fd < 0) {
        napi_throw_error(env, nullptr, "invalid TUN fd");
        return nullptr;
    }

    pthread_mutex_lock(&g_tunMutex);
    if (g_tunCtx.threadStarted) {
        StopTunReadThreadInternal();
    }

    napi_value resourceName;
    napi_create_string_utf8(
        env, "TunReadThread", NAPI_AUTO_LENGTH, &resourceName);
    napi_status tsfnStatus = napi_create_threadsafe_function(
        env, args[1], nullptr, resourceName, 256, 1, nullptr, nullptr,
        nullptr, TunReadTSFNCallback, &g_tunCtx.tsfn);
    if (tsfnStatus != napi_ok) {
        pthread_mutex_unlock(&g_tunMutex);
        napi_throw_error(
            env, nullptr, "create TUN threadsafe callback failed");
        return nullptr;
    }

    g_tunCtx.fd = fd;
    g_tunCtx.running.store(true);
    const int threadResult = pthread_create(
        &g_tunCtx.thread, nullptr, TunReadThreadMain, &g_tunCtx);
    if (threadResult != 0) {
        g_tunCtx.running.store(false);
        napi_release_threadsafe_function(
            g_tunCtx.tsfn, napi_tsfn_abort);
        g_tunCtx.tsfn = nullptr;
        g_tunCtx.fd = -1;
        pthread_mutex_unlock(&g_tunMutex);
        napi_throw_error(env, nullptr, strerror(threadResult));
        return nullptr;
    }
    g_tunCtx.threadStarted = true;
    pthread_mutex_unlock(&g_tunMutex);

    napi_value result;
    napi_get_boolean(env, true, &result);
    return result;
}

static napi_value StopTunReadThread(
    napi_env env, napi_callback_info info) {
    pthread_mutex_lock(&g_tunMutex);
    StopTunReadThreadInternal();
    pthread_mutex_unlock(&g_tunMutex);

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static void TSFNCallback(napi_env env, napi_value jsCallback, void* context, void* data) {
    RecvData* rd = static_cast<RecvData*>(data);
    if (rd == nullptr) return;

    // 仅抽样回调累计统计，不把每个 WG 包排入 ArkTS 主线程。
    napi_value args[6];
    napi_create_double(env, static_cast<double>(rd->rxBytes), &args[0]);
    napi_create_double(env, static_cast<double>(rd->rxPackets), &args[1]);
    napi_create_double(env, static_cast<double>(rd->txBytes), &args[2]);
    napi_create_double(env, static_cast<double>(rd->txPackets), &args[3]);
    napi_create_double(env, static_cast<double>(rd->lastPacketLen), &args[4]);
    napi_create_int32(env, rd->direction, &args[5]);
    napi_call_function(env, nullptr, jsCallback, 6, args, nullptr);

    delete rd;
}

static void QueueStats(RecvThreadCtx* ctx, size_t lastPacketLen, int direction) {
    const uint64_t packets =
        direction == 0 ? ctx->rxPackets.load() : ctx->txPackets.load();
    if (packets > 200 && packets % 100 != 1) return;

    RecvData* rd = new RecvData();
    rd->rxBytes = ctx->rxBytes.load();
    rd->rxPackets = ctx->rxPackets.load();
    rd->txBytes = ctx->txBytes.load();
    rd->txPackets = ctx->txPackets.load();
    rd->lastPacketLen = lastPacketLen;
    rd->direction = direction;
    napi_status status =
        napi_call_threadsafe_function(ctx->tsfn, rd, napi_tsfn_nonblocking);
    if (status != napi_ok) {
        delete rd;
    }
}

static void* RecvThreadFunc(void* arg) {
    RecvThreadCtx* ctx = static_cast<RecvThreadCtx*>(arg);
    uint8_t buf[65536];

    while (ctx->running.load()) {
        struct pollfd pfds[2];
        pfds[0].fd = ctx->fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = ctx->relayFd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        int ret = poll(pfds, 2, 500);
        if (ret <= 0) continue;

        // WG 服务器 → VpnExtension。
        if ((pfds[0].revents & POLLIN) != 0) {
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            ssize_t n = recvfrom(ctx->fd, buf, sizeof(buf), 0,
                                 reinterpret_cast<struct sockaddr*>(&from), &fromLen);
            if (n > 0) {
                struct sockaddr_in loopback;
                memset(&loopback, 0, sizeof(loopback));
                loopback.sin_family = AF_INET;
                loopback.sin_port = htons(static_cast<uint16_t>(ctx->forwardPort));
                loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                ssize_t sent;
                do {
                    sent = sendto(ctx->forwardFd, buf, static_cast<size_t>(n), 0,
                                  reinterpret_cast<struct sockaddr*>(&loopback),
                                  sizeof(loopback));
                } while (sent < 0 && errno == EINTR);
                if (sent == n) {
                    ctx->rxBytes.fetch_add(static_cast<uint64_t>(n));
                    ctx->rxPackets.fetch_add(1);
                    QueueStats(ctx, static_cast<size_t>(n), 0);
                }
            }
        }

        // VpnExtension → 本机 relayPort → WG 服务器。
        if ((pfds[1].revents & POLLIN) != 0) {
            struct sockaddr_in from;
            socklen_t fromLen = sizeof(from);
            ssize_t n = recvfrom(ctx->relayFd, buf, sizeof(buf), 0,
                                 reinterpret_cast<struct sockaddr*>(&from), &fromLen);
            if (n > 0) {
                ssize_t sent;
                do {
                    sent = sendto(ctx->fd, buf, static_cast<size_t>(n), 0,
                                  reinterpret_cast<struct sockaddr*>(&ctx->remoteAddr),
                                  sizeof(ctx->remoteAddr));
                } while (sent < 0 && errno == EINTR);
                if (sent == n) {
                    ctx->txBytes.fetch_add(static_cast<uint64_t>(n));
                    ctx->txPackets.fetch_add(1);
                    QueueStats(ctx, static_cast<size_t>(n), 1);
                }
            }
        }
    }

    return nullptr;
}

static napi_value StartRecvThread(napi_env env, napi_callback_info info) {
    size_t argc = 6;
    napi_value args[6];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 6) {
        napi_throw_error(
            env, nullptr,
            "expected 6 args (fd, relayPort, forwardPort, remoteHost, remotePort, callback)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);
    int relayPort;
    napi_get_value_int32(env, args[1], &relayPort);
    int forwardPort;
    napi_get_value_int32(env, args[2], &forwardPort);
    std::string remoteHost = GetString(env, args[3]);
    int remotePort;
    napi_get_value_int32(env, args[4], &remotePort);
    if (relayPort <= 0 || relayPort > 65535 ||
        forwardPort <= 0 || forwardPort > 65535 ||
        remotePort <= 0 || remotePort > 65535) {
        napi_throw_error(env, nullptr, "invalid relay or remote port");
        return nullptr;
    }

    // args[5] is the low-rate statistics callback.
    napi_value callback = args[5];

    pthread_mutex_lock(&g_ctxMutex);

    if (g_ctx.running.load()) {
        pthread_mutex_unlock(&g_ctxMutex);
        napi_value result;
        napi_get_boolean(env, false, &result);
        return result;
    }

    g_ctx.fd = fd;
    g_ctx.forwardPort = forwardPort;
    memset(&g_ctx.remoteAddr, 0, sizeof(g_ctx.remoteAddr));
    g_ctx.remoteAddr.sin_family = AF_INET;
    g_ctx.remoteAddr.sin_port = htons(static_cast<uint16_t>(remotePort));
    if (inet_pton(AF_INET, remoteHost.c_str(), &g_ctx.remoteAddr.sin_addr) <= 0) {
        pthread_mutex_unlock(&g_ctxMutex);
        napi_throw_error(env, nullptr, "invalid remoteHost");
        return nullptr;
    }
    g_ctx.forwardFd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_ctx.forwardFd < 0) {
        pthread_mutex_unlock(&g_ctxMutex);
        napi_throw_error(env, nullptr, "loopback socket() failed");
        return nullptr;
    }
    g_ctx.relayFd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_ctx.relayFd < 0) {
        close(g_ctx.forwardFd);
        g_ctx.forwardFd = -1;
        pthread_mutex_unlock(&g_ctxMutex);
        napi_throw_error(env, nullptr, "relay socket() failed");
        return nullptr;
    }
    int reuseAddress = 1;
    setsockopt(g_ctx.relayFd, SOL_SOCKET, SO_REUSEADDR,
               &reuseAddress, sizeof(reuseAddress));
    struct sockaddr_in relayAddr;
    memset(&relayAddr, 0, sizeof(relayAddr));
    relayAddr.sin_family = AF_INET;
    relayAddr.sin_port = htons(static_cast<uint16_t>(relayPort));
    relayAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(g_ctx.relayFd, reinterpret_cast<struct sockaddr*>(&relayAddr),
             sizeof(relayAddr)) < 0) {
        close(g_ctx.relayFd);
        close(g_ctx.forwardFd);
        g_ctx.relayFd = -1;
        g_ctx.forwardFd = -1;
        pthread_mutex_unlock(&g_ctxMutex);
        napi_throw_error(env, nullptr, "relay bind() failed");
        return nullptr;
    }
    int socketBufferSize = 4 * 1024 * 1024;
    setsockopt(g_ctx.fd, SOL_SOCKET, SO_RCVBUF,
               &socketBufferSize, sizeof(socketBufferSize));
    setsockopt(g_ctx.forwardFd, SOL_SOCKET, SO_SNDBUF,
               &socketBufferSize, sizeof(socketBufferSize));
    setsockopt(g_ctx.relayFd, SOL_SOCKET, SO_RCVBUF,
               &socketBufferSize, sizeof(socketBufferSize));
    g_ctx.rxBytes.store(0);
    g_ctx.rxPackets.store(0);
    g_ctx.txBytes.store(0);
    g_ctx.txPackets.store(0);
    g_ctx.running.store(true);

    // Create threadsafe function for callback
    napi_value tsfnName;
    napi_create_string_utf8(env, "recvCallback", NAPI_AUTO_LENGTH, &tsfnName);

    napi_status tsfnStatus = napi_create_threadsafe_function(
        env, callback, nullptr, tsfnName,
        0, 1, nullptr, nullptr, nullptr,
        TSFNCallback, &g_ctx.tsfn);

    if (tsfnStatus != napi_ok) {
        g_ctx.running.store(false);
        close(g_ctx.relayFd);
        close(g_ctx.forwardFd);
        g_ctx.relayFd = -1;
        g_ctx.forwardFd = -1;
        pthread_mutex_unlock(&g_ctxMutex);
        napi_throw_error(env, nullptr, "napi_create_threadsafe_function failed");
        return nullptr;
    }

    pthread_create(&g_ctx.thread, nullptr, RecvThreadFunc, &g_ctx);

    pthread_mutex_unlock(&g_ctxMutex);

    napi_value result;
    napi_get_boolean(env, true, &result);
    return result;
}

static napi_value StopRecvThread(napi_env env, napi_callback_info info) {
    pthread_mutex_lock(&g_ctxMutex);

    if (g_ctx.running.load()) {
        g_ctx.running.store(false);
        pthread_join(g_ctx.thread, nullptr);

        napi_release_threadsafe_function(g_ctx.tsfn, napi_tsfn_release);
        g_ctx.tsfn = nullptr;
        if (g_ctx.forwardFd >= 0) {
            close(g_ctx.forwardFd);
            g_ctx.forwardFd = -1;
        }
        if (g_ctx.relayFd >= 0) {
            close(g_ctx.relayFd);
            g_ctx.relayFd = -1;
        }
    }

    pthread_mutex_unlock(&g_ctxMutex);

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ── 创建 UDP Socket ──

static napi_value CreateUdpSocket(napi_env env, napi_callback_info info) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        napi_throw_error(env, nullptr, "socket() failed");
        return nullptr;
    }
    napi_value result;
    napi_create_int32(env, fd, &result);
    return result;
}

// ── 发送数据 ──

static napi_value UdpSendTo(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value args[4];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 4) {
        napi_throw_error(env, nullptr, "expected 4 args (fd, data, host, port)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);

    void* buf = nullptr;
    size_t len = 0;
    napi_get_arraybuffer_info(env, args[1], &buf, &len);

    std::string host = GetString(env, args[2]);
    int port;
    napi_get_value_int32(env, args[3], &port);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &dest.sin_addr) <= 0) {
        napi_throw_error(env, nullptr, "inet_pton failed");
        return nullptr;
    }

    ssize_t sent = sendto(fd, buf, len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }

    napi_value result;
    napi_create_int32(env, sent < 0 ? 0 : static_cast<int32_t>(sent), &result);
    return result;
}

// ── 接收数据（带超时） ──

static napi_value UdpRecvFrom(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 3) {
        napi_throw_error(env, nullptr, "expected 3 args (fd, bufSize, timeoutMs)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);
    int bufSize;
    napi_get_value_int32(env, args[1], &bufSize);
    if (bufSize <= 0 || bufSize > 65535) bufSize = 65535;
    int timeoutMs;
    napi_get_value_int32(env, args[2], &timeoutMs);

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, timeoutMs);
    if (ret == 0) {
        napi_value result;
        napi_get_null(env, &result);
        return result;
    }
    if (ret < 0) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }

    char stackBuf[65536];
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    ssize_t received = recvfrom(fd, stackBuf, sizeof(stackBuf), 0,
                                (struct sockaddr*)&from, &fromLen);
    if (received <= 0) {
        napi_value result;
        napi_get_null(env, &result);
        return result;
    }

    napi_value arrayBuffer;
    void* abPtr = nullptr;
    napi_create_arraybuffer(env, static_cast<size_t>(received), &abPtr, &arrayBuffer);
    memcpy(abPtr, stackBuf, static_cast<size_t>(received));

    napi_value result;
    napi_create_object(env, &result);
    napi_set_named_property(env, result, "data", arrayBuffer);

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, ipStr, sizeof(ipStr));

    napi_value fromObj, jsIP, jsPort;
    napi_create_object(env, &fromObj);
    napi_create_string_utf8(env, ipStr, NAPI_AUTO_LENGTH, &jsIP);
    napi_create_int32(env, ntohs(from.sin_port), &jsPort);
    napi_set_named_property(env, fromObj, "address", jsIP);
    napi_set_named_property(env, fromObj, "port", jsPort);
    napi_set_named_property(env, result, "from", fromObj);

    return result;
}

// ── 通用非阻塞 fd 读写（用于 VpnExtension 的 TUN） ──

static napi_value ReadFd(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 2) {
        napi_throw_error(env, nullptr, "expected 2 args (fd, maxLength)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);
    int maxLength;
    napi_get_value_int32(env, args[1], &maxLength);
    if (fd < 0 || maxLength <= 0 || maxLength > 65536) {
        napi_throw_error(env, nullptr, "invalid fd or maxLength");
        return nullptr;
    }

    uint8_t buffer[65536];
    ssize_t bytesRead;
    do {
        bytesRead = read(fd, buffer, static_cast<size_t>(maxLength));
    } while (bytesRead < 0 && errno == EINTR);

    if (bytesRead < 0 &&
        (errno == EAGAIN || errno == EWOULDBLOCK)) {
        napi_value result;
        napi_get_null(env, &result);
        return result;
    }
    if (bytesRead < 0) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }
    if (bytesRead == 0) {
        napi_value result;
        napi_get_null(env, &result);
        return result;
    }

    napi_value arrayBuffer;
    void* output = nullptr;
    napi_create_arraybuffer(
        env, static_cast<size_t>(bytesRead), &output, &arrayBuffer);
    memcpy(output, buffer, static_cast<size_t>(bytesRead));
    return arrayBuffer;
}

static napi_value WriteFd(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 2) {
        napi_throw_error(env, nullptr, "expected 2 args (fd, data)");
        return nullptr;
    }

    int fd;
    napi_get_value_int32(env, args[0], &fd);
    void* buffer = nullptr;
    size_t length = 0;
    napi_get_arraybuffer_info(env, args[1], &buffer, &length);
    if (fd < 0 || buffer == nullptr || length == 0) {
        napi_throw_error(env, nullptr, "invalid fd or data");
        return nullptr;
    }

    ssize_t bytesWritten;
    do {
        bytesWritten = write(fd, buffer, length);
    } while (bytesWritten < 0 && errno == EINTR);

    if (bytesWritten < 0 &&
        (errno == EAGAIN || errno == EWOULDBLOCK)) {
        bytesWritten = 0;
    } else if (bytesWritten < 0) {
        napi_throw_error(env, nullptr, strerror(errno));
        return nullptr;
    }

    napi_value result;
    napi_create_int32(env, static_cast<int32_t>(bytesWritten), &result);
    return result;
}

// ── 关闭 ──

static napi_value CloseUdpSocket(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < 1) {
        napi_throw_error(env, nullptr, "expected 1 argument (fd)");
        return nullptr;
    }
    int fd;
    napi_get_value_int32(env, args[0], &fd);

    pthread_mutex_lock(&g_ctxMutex);
    close(fd);
    pthread_mutex_unlock(&g_ctxMutex);

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

// ── 模块注册 ──

static napi_value Init(napi_env env, napi_value exports) {
    auto def = [&](const char* name, napi_callback func) {
        napi_property_descriptor d = {};
        d.utf8name = name;
        d.method = func;
        d.attributes = napi_default;
        napi_define_properties(env, exports, 1, &d);
    };
    def("createUdpSocket", CreateUdpSocket);
    def("udpSendTo", UdpSendTo);
    def("udpRecvFrom", UdpRecvFrom);
    def("readFd", ReadFd);
    def("writeFd", WriteFd);
    def("startTunReadThread", StartTunReadThread);
    def("stopTunReadThread", StopTunReadThread);
    def("closeUdpSocket", CloseUdpSocket);
    def("startRecvThread", StartRecvThread);
    def("stopRecvThread", StopRecvThread);
    return exports;
}

static napi_module udpSocketModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "udp_socket",
    .nm_priv = nullptr,
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterUdpSocketModule(void) {
    napi_module_register(&udpSocketModule);
}
