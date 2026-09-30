// inspect.cpp - one fully instrumented TLS handshake (for the live dashboard)
#include "inspect.hpp"

#include "json.hpp"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <memory>

namespace tlsf {

namespace {

using Clock = std::chrono::steady_clock;
using CtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;

double ms_between(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

bool is_ip_literal(const std::string& h) {
    unsigned char buf[16];
    return inet_pton(AF_INET, h.c_str(), buf) == 1 || inet_pton(AF_INET6, h.c_str(), buf) == 1;
}

void set_timeout(int fd, int ms) {
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

int connect_with_timeout(const addrinfo* ai, int ms) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc < 0) {
        pollfd p{fd, POLLOUT, 0};
        int err = 0;
        socklen_t len = sizeof err;
        if (poll(&p, 1, ms) <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) {
            close(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, flags);
    return fd;
}

std::string bio_string(BIO* b) {
    char* data = nullptr;
    long n = BIO_get_mem_data(b, &data);
    std::string s(data ? data : "", n > 0 ? static_cast<size_t>(n) : 0);
    BIO_free(b);
    return s;
}

std::string name_string(const X509_NAME* n) {
    BIO* b = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(b, n, 0, (XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB) | ASN1_STRFLGS_UTF8_CONVERT);
    return bio_string(b);
}

std::string time_string(const ASN1_TIME* t) {
    BIO* b = BIO_new(BIO_s_mem());
    ASN1_TIME_print(b, t);
    return bio_string(b);
}

CertInfo cert_info(X509* x) {
    CertInfo c;
    c.subject = name_string(X509_get_subject_name(x));
    c.issuer = name_string(X509_get_issuer_name(x));
    c.not_before = time_string(X509_get0_notBefore(x));
    c.not_after = time_string(X509_get0_notAfter(x));
    const char* sig = OBJ_nid2ln(X509_get_signature_nid(x));
    c.sigalg = sig ? sig : "unknown";

    if (EVP_PKEY* pk = X509_get0_pubkey(x)) {
        const char* t = EVP_PKEY_get0_type_name(pk);
        c.key = t ? t : "unknown";
        char group[64] = {0};
        size_t glen = 0;
        if (EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &glen))
            c.key += std::string(" ") + group;
        else
            c.key += " " + std::to_string(EVP_PKEY_get_bits(pk)) + "-bit";
    }

    auto* names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr));
    if (names) {
        for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
            const GENERAL_NAME* g = sk_GENERAL_NAME_value(names, i);
            if (g->type != GEN_DNS) continue;
            c.san_total++;
            if (c.sans.size() < 10)
                c.sans.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)),
                                    ASN1_STRING_length(g->d.dNSName));
        }
        GENERAL_NAMES_free(names);
    }
    ERR_clear_error();
    return c;
}

std::string version_name(uint16_t v) {
    switch (v) {
        case 0x0304: return "TLS 1.3";
        case 0x0303: return "TLS 1.2";
        case 0x0302: return "TLS 1.1";
        case 0x0301: return "TLS 1.0";
        default: return is_grease(v) ? "GREASE" : "0x" + std::to_string(v);
    }
}

}  // namespace

InspectResult inspect(const ClientConfig& c, const InspectOptions& o) {
    InspectResult r;
    r.cfg = c;
    r.host = c.host;
    r.port = c.port;
    ERR_clear_error();

    CtxPtr ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!ctx) { r.error = "SSL_CTX_new: " + openssl_errors(); return r; }
    std::string err = apply_offer(ctx.get(), c);
    if (!err.empty()) { r.rejected_locally = true; r.error = err; return r; }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);  // record, don't abort
    SSL_CTX_set_default_verify_paths(ctx.get());
    if (!o.alpn.empty()) {
        std::vector<unsigned char> wire;
        for (const auto& a : o.alpn) {
            wire.push_back(static_cast<unsigned char>(a.size()));
            wire.insert(wire.end(), a.begin(), a.end());
        }
        SSL_CTX_set_alpn_protos(ctx.get(), wire.data(), static_cast<unsigned>(wire.size()));
    }

    // 1. DNS (prefer IPv4: it works on more networks)
    auto t0 = Clock::now();
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    int rc = getaddrinfo(c.host.c_str(), c.port.c_str(), &hints, &res);
    if (rc != 0) {
        hints.ai_family = AF_UNSPEC;
        rc = getaddrinfo(c.host.c_str(), c.port.c_str(), &hints, &res);
    }
    if (rc != 0) { r.error = std::string("DNS lookup failed: ") + gai_strerror(rc); return r; }
    auto t1 = Clock::now();
    r.dns_ms = ms_between(t0, t1);

    // 2. TCP (one network round trip)
    int fd = -1;
    for (addrinfo* ai = res; ai && fd < 0; ai = ai->ai_next) {
        fd = connect_with_timeout(ai, o.timeout_ms);
        char h[NI_MAXHOST];
        if (fd >= 0 && getnameinfo(ai->ai_addr, ai->ai_addrlen, h, sizeof h, nullptr, 0, NI_NUMERICHOST) == 0)
            r.ip = h;
    }
    freeaddrinfo(res);
    if (fd < 0) { r.error = "TCP connect to " + c.host + ":" + c.port + " failed or timed out"; return r; }
    auto t2 = Clock::now();
    r.tcp_ms = ms_between(t1, t2);
    set_timeout(fd, o.timeout_ms);

    // 3. TLS
    SslPtr ssl(SSL_new(ctx.get()), SSL_free);
    BIO* bio = BIO_new_socket(fd, BIO_CLOSE);
    SSL_set_bio(ssl.get(), bio, bio);
    const std::string name = c.sni.empty() ? c.host : c.sni;
    if (!is_ip_literal(name)) {
        SSL_set_tlsext_host_name(ssl.get(), name.c_str());
        SSL_set1_host(ssl.get(), name.c_str());
    }
    r.trace.t0 = t2;
    attach_trace(ssl.get(), &r.trace);

    int hs = SSL_connect(ssl.get());
    r.tls_ms = ms_between(t2, Clock::now());
    if (hs == 1) {
        r.ok = true;
        r.neg = describe(ssl.get());
        const unsigned char* a = nullptr;
        unsigned alen = 0;
        SSL_get0_alpn_selected(ssl.get(), &a, &alen);
        if (a) r.alpn.assign(reinterpret_cast<const char*>(a), alen);
    } else {
        r.error = openssl_errors();
    }

    if (STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl.get())) {
        for (int i = 0; i < sk_X509_num(chain); ++i) r.chain.push_back(cert_info(sk_X509_value(chain, i)));
        long v = SSL_get_verify_result(ssl.get());
        r.verify_ok = v == X509_V_OK;
        r.verify = X509_verify_cert_error_string(v);
    }

    // 4. TLS 1.3 servers send NewSessionTicket right after the handshake.
    if (r.ok && o.wait_for_tickets) {
        set_timeout(fd, 350);
        char buf[4096];
        for (int i = 0; i < 3 && SSL_read(ssl.get(), buf, sizeof buf) > 0; ++i) {}
    }
    ERR_clear_error();
    if (r.ok) SSL_shutdown(ssl.get());
    ERR_clear_error();

    for (const auto& h : r.trace.hellos) r.hellos.push_back(parse_hello(h));
    return r;
}

std::string to_json(const InspectResult& r) {
    using namespace json;

    bool tls13 = r.ok ? r.neg.version == "TLSv1.3" : false;
    if (!r.ok)
        for (const auto& h : r.hellos)
            if (!h.client && !h.hrr && !h.versions.empty() && h.versions[0] == 0x0304) tls13 = true;

    // Work out which messages travelled encrypted.
    std::vector<TraceEvent> evs;
    for (const auto& e : r.trace.events) {
        // Our own close_notify when we hang up is not part of the story.
        if (e.content_type == SSL3_RT_ALERT && e.sent && e.detail == 0) continue;
        // OpenSSL's message callback doesn't report the server's TLS 1.2
        // ChangeCipherSpec, so put it back in front of the server's Finished.
        if (!tls13 && !e.sent && e.content_type == SSL3_RT_HANDSHAKE && e.detail == 20) {
            bool have = false;
            for (const auto& x : evs) have |= !x.sent && x.content_type == SSL3_RT_CHANGE_CIPHER_SPEC;
            if (!have) evs.push_back({false, SSL3_RT_CHANGE_CIPHER_SPEC, 1, false, 1, e.t_ms});
        }
        evs.push_back(e);
    }

    std::vector<std::string> events;
    bool real_sh = false, ccs_out = false, ccs_in = false;
    for (const auto& e : evs) {
        std::string name, kind;
        bool enc = false;
        if (e.content_type == SSL3_RT_CHANGE_CIPHER_SPEC) {
            name = "ChangeCipherSpec";
            kind = tls13 ? "compat" : "ccs";
            (e.sent ? ccs_out : ccs_in) = true;
        } else if (e.content_type == SSL3_RT_ALERT) {
            name = std::string("Alert: ") + SSL_alert_desc_string_long(e.detail);
            kind = "alert";
            enc = tls13 ? real_sh : (e.sent ? ccs_out : ccs_in);
        } else {
            name = handshake_type_name(e.detail, e.hrr);
            kind = e.hrr ? "hrr" : "handshake";
            enc = tls13 ? (real_sh && e.detail != 1 && e.detail != 2) : (e.sent ? ccs_out : ccs_in);
            if (e.detail == 2 && !e.hrr) real_sh = true;
        }
        events.push_back(obj({{"dir", str(e.sent ? "out" : "in")},
                              {"name", str(name)},
                              {"kind", str(kind)},
                              {"type", num(static_cast<long long>(e.detail))},
                              {"len", num(static_cast<long long>(e.len))},
                              {"t", num(e.t_ms)},
                              {"encrypted", boolean(enc)},
                              {"post", boolean(r.ok && e.t_ms > r.tls_ms)}}));
    }

    auto names16 = [](const std::vector<uint16_t>& v, std::string (*f)(uint16_t)) {
        return arr(v, [f](uint16_t x) { return str(f(x)); });
    };
    auto hello_json = [&](const HelloInfo& h) {
        return obj({{"client", boolean(h.client)},
                    {"hrr", boolean(h.hrr)},
                    {"length", num(static_cast<long long>(h.length))},
                    {"suites", names16(h.suites, cipher_id_name)},
                    {"groups", names16(h.groups, group_id_name)},
                    {"sigalgs", names16(h.sigalgs, sigalg_id_name)},
                    {"versions", names16(h.versions, version_name)},
                    {"extensions", names16(h.extensions, ext_name)},
                    {"key_shares", arr(h.key_shares, [](const KeyShare& k) {
                         return obj({{"group", str(group_id_name(k.group))},
                                     {"len", num(static_cast<long long>(k.len))}});
                     })},
                    {"alpn", strs(h.alpn)},
                    {"sni", str(h.sni)}});
    };
    auto cert_json = [](const CertInfo& c) {
        return obj({{"subject", str(c.subject)},
                    {"issuer", str(c.issuer)},
                    {"key", str(c.key)},
                    {"sigalg", str(c.sigalg)},
                    {"not_before", str(c.not_before)},
                    {"not_after", str(c.not_after)},
                    {"sans", strs(c.sans)},
                    {"san_total", num(static_cast<long long>(c.san_total))}});
    };

    return obj({
        {"ok", boolean(r.ok)},
        {"rejected_locally", boolean(r.rejected_locally)},
        {"error", str(r.error)},
        {"host", str(r.host)},
        {"port", str(r.port)},
        {"ip", str(r.ip)},
        {"offer", obj({{"groups", str(r.cfg.groups)},
                       {"sigalgs", str(r.cfg.sigalgs)},
                       {"suites", str(r.cfg.ciphersuites)},
                       {"ciphers", str(r.cfg.cipher_list)},
                       {"version", str(r.cfg.max_version == TLS1_2_VERSION   ? "1.2"
                                       : r.cfg.min_version == TLS1_3_VERSION ? "1.3"
                                                                             : "auto")}})},
        {"timing", obj({{"dns", num(r.dns_ms)}, {"tcp", num(r.tcp_ms)}, {"tls", num(r.tls_ms)}})},
        {"negotiated", obj({{"version", str(r.neg.version)},
                            {"cipher", str(r.neg.cipher)},
                            {"group", str(r.neg.group)},
                            {"sig", str(r.neg.peer_sig)},
                            {"sig_iana", str(r.neg.peer_sig_iana)},
                            {"alpn", str(r.alpn)}})},
        {"hrr", boolean(r.trace.hrr)},
        {"client_hellos", num(static_cast<long long>(r.trace.client_hellos))},
        {"events", arr(events)},
        {"hellos", arr(r.hellos, hello_json)},
        {"chain", arr(r.chain, cert_json)},
        {"verify", obj({{"ok", boolean(r.verify_ok)}, {"text", str(r.verify)}})},
    });
}

}  // namespace tlsf
