/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "http.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace avb {

namespace {

constexpr size_t kMaxHeaderBytes = 64 * 1024;

const char* reason(int status) {
    switch (status) {
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 501: return "Not Implemented";
    default: return "Internal Server Error";
    }
}

bool sendAll(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

std::string toLower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

} // namespace

std::string urlDecode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hex(s[i + 1]), lo = hex(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        out += (s[i] == '+') ? ' ' : s[i];
    }
    return out;
}

bool HttpServer::listenAndServe(std::string& err) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "socket() failed";
        return false;
    }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(mPort);
    if (::bind(fd, (sockaddr*)&addr, sizeof addr) != 0) {
        err = "bind() failed on port " + std::to_string(mPort) +
              " (already in use?)";
        ::close(fd);
        return false;
    }
    if (::listen(fd, 128) != 0) {
        err = "listen() failed";
        ::close(fd);
        return false;
    }
    mListenFd.store(fd);

    while (!mStopping.load()) {
        sockaddr_in peer{};
        socklen_t plen = sizeof peer;
        int cfd = ::accept(fd, (sockaddr*)&peer, &plen);
        if (cfd < 0) {
            if (mStopping.load()) break;
            continue;
        }
        char ip[INET_ADDRSTRLEN] = "?";
        ::inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
        std::string peerAddr =
            std::string(ip) + ":" + std::to_string(ntohs(peer.sin_port));

        timeval tv{30, 0};
        ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ::setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        int nd = 1;
        ::setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof nd);

        mPool.post([this, cfd, peerAddr] { handleConnection(cfd, peerAddr); });
    }
    ::close(fd);
    return true;
}

void HttpServer::stop() {
    mStopping.store(true);
    int fd = mListenFd.exchange(-1);
    if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
}

bool HttpServer::readRequest(int fd, std::string& buffered, HttpRequest& req,
                             int& httpErr) {
    // Accumulate until the header terminator.
    size_t headerEnd;
    while ((headerEnd = buffered.find("\r\n\r\n")) == std::string::npos) {
        if (buffered.size() > kMaxHeaderBytes) {
            httpErr = 431;
            return false;
        }
        char buf[16 * 1024];
        ssize_t n = ::recv(fd, buf, sizeof buf, 0);
        if (n <= 0) {
            httpErr = 0; // closed / timeout — not an error to report
            return false;
        }
        buffered.append(buf, (size_t)n);
    }

    std::string head = buffered.substr(0, headerEnd);
    std::string rest = buffered.substr(headerEnd + 4);

    // Request line.
    size_t lineEnd = head.find("\r\n");
    std::string reqLine = head.substr(0, lineEnd);
    size_t sp1 = reqLine.find(' ');
    size_t sp2 = reqLine.rfind(' ');
    if (sp1 == std::string::npos || sp2 == sp1) {
        httpErr = 400;
        return false;
    }
    req.method = reqLine.substr(0, sp1);
    std::string target = reqLine.substr(sp1 + 1, sp2 - sp1 - 1);

    size_t qpos = target.find('?');
    req.path = urlDecode(target.substr(0, qpos));
    if (qpos != std::string::npos) {
        std::string qs = target.substr(qpos + 1);
        size_t start = 0;
        while (start <= qs.size()) {
            size_t amp = qs.find('&', start);
            std::string kv = qs.substr(
                start, amp == std::string::npos ? std::string::npos : amp - start);
            if (!kv.empty()) {
                size_t eq = kv.find('=');
                if (eq == std::string::npos)
                    req.query[urlDecode(kv)] = "";
                else
                    req.query[urlDecode(kv.substr(0, eq))] =
                        urlDecode(kv.substr(eq + 1));
            }
            if (amp == std::string::npos) break;
            start = amp + 1;
        }
    }

    // Headers.
    size_t pos = lineEnd + 2;
    while (pos < head.size()) {
        size_t end = head.find("\r\n", pos);
        if (end == std::string::npos) end = head.size();
        std::string line = head.substr(pos, end - pos);
        pos = end + 2;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = toLower(line.substr(0, colon));
        size_t vstart = line.find_first_not_of(" \t", colon + 1);
        req.headers[name] =
            vstart == std::string::npos ? "" : line.substr(vstart);
    }

    if (!req.header("transfer-encoding").empty()) {
        httpErr = 501;
        return false;
    }

    // Body.
    size_t contentLength = 0;
    if (auto cl = req.header("content-length"); !cl.empty()) {
        char* end = nullptr;
        unsigned long long v = std::strtoull(cl.c_str(), &end, 10);
        if (!end || *end != '\0') {
            httpErr = 400;
            return false;
        }
        contentLength = (size_t)v;
    }
    if (contentLength > mMaxBody) {
        httpErr = 413;
        return false;
    }
    while (rest.size() < contentLength) {
        char buf[64 * 1024];
        size_t want = std::min(sizeof buf, contentLength - rest.size());
        ssize_t n = ::recv(fd, buf, want, 0);
        if (n <= 0) {
            httpErr = 0;
            return false;
        }
        rest.append(buf, (size_t)n);
    }
    req.body = rest.substr(0, contentLength);
    buffered = rest.substr(contentLength); // possible pipelined next request
    return true;
}

void HttpServer::writeResponse(int fd, const HttpResponse& resp, bool close,
                               ClientInfo* client) {
    std::string head = "HTTP/1.1 " + std::to_string(resp.status) + " " +
                       reason(resp.status) + "\r\n";
    head += "Content-Type: " + resp.contentType + "\r\n";
    head += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
    head += close ? "Connection: close\r\n" : "Connection: keep-alive\r\n";
    for (auto& [k, v] : resp.extraHeaders) head += k + ": " + v + "\r\n";
    head += "\r\n";
    if (sendAll(fd, head.data(), head.size()))
        sendAll(fd, resp.body.data(), resp.body.size());
    if (client) client->bytesSent += head.size() + resp.body.size();
}

void HttpServer::handleConnection(int fd, const std::string& addr) {
    auto client = mClients.add(addr, "http");
    std::string buffered;

    while (!mStopping.load()) {
        HttpRequest req;
        req.clientAddr = addr;
        int httpErr = 500;
        if (!readRequest(fd, buffered, req, httpErr)) {
            if (httpErr) {
                HttpResponse resp;
                resp.status = httpErr == 431 ? 400 : httpErr;
                resp.body = "{\"error\":\"malformed request\"}";
                writeResponse(fd, resp, true, client.get());
            }
            break;
        }
        client->messages++;

        // WebSocket upgrade — hand the socket to the API layer.
        if (toLower(req.header("upgrade")) == "websocket" && mUpgrade) {
            mClients.remove(client); // the WS path registers its own entry
            if (!mUpgrade(req, fd, nullptr)) ::close(fd);
            return;
        }

        HttpResponse resp;
        bool close = toLower(req.header("connection")) == "close";
        if (mHandler) {
            try {
                mHandler(req, resp, client);
            } catch (const std::exception& e) {
                resp = HttpResponse{};
                resp.status = 500;
                resp.body = "{\"error\":\"internal error\"}";
            }
        } else {
            resp.status = 404;
            resp.body = "{\"error\":\"no handler\"}";
        }
        writeResponse(fd, resp, close, client.get());
        if (close) break;
    }

    ::close(fd);
    mClients.remove(client);
}

} // namespace avb
