// tls_util.hpp - shared helpers for tls-forcer (client, server, prober)
#pragma once

#include <openssl/ssl.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace tlsf {

// Drains the OpenSSL error queue into one readable line.
std::string openssl_errors();

// IANA code point -> human name (NamedGroup, SignatureScheme).
std::string group_id_name(uint16_t id);
std::string sigalg_id_name(uint16_t id);
bool is_grease(uint16_t id);  // RFC 8701 GREASE values (browsers send these)

// Loads extra OpenSSL providers, e.g. "oqsprovider" for post-quantum groups.
void load_providers(const std::vector<std::string>& names);

std::string cipher_id_name(uint16_t id);     // IANA suite id -> standard name
std::string ext_name(uint16_t id);           // extension type -> name
std::string handshake_type_name(int type, bool hrr);

// One TLS message seen on the wire (handshake, ChangeCipherSpec or alert).
struct TraceEvent {
    bool sent;          // true = we wrote it, false = we received it
    int content_type;   // 20 CCS, 21 alert, 22 handshake
    int detail;         // handshake type, or alert description
    bool hrr;           // ServerHello that is really a HelloRetryRequest
    size_t len;
    double t_ms;        // time since Trace::t0
};

// Watches raw handshake messages. Counts ClientHellos, spots a
// HelloRetryRequest (a ServerHello whose random is the fixed HRR magic value),
// and keeps a timeline plus raw copies of every Client/ServerHello.
struct Trace {
    int client_hellos = 0;
    bool hrr = false;
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
    std::vector<TraceEvent> events;
    std::vector<std::vector<unsigned char>> hellos;  // raw CH / SH, in order
};
void attach_trace(SSL* ssl, Trace* trace);

// Decoded Client/ServerHello (works on the raw bytes from Trace::hellos).
struct KeyShare {
    uint16_t group;
    size_t len;
};
struct HelloInfo {
    bool ok = false;
    bool client = false;
    bool hrr = false;
    std::vector<uint16_t> suites;       // ClientHello: offered, ServerHello: [chosen]
    std::vector<uint16_t> groups, sigalgs, versions, extensions;
    std::vector<KeyShare> key_shares;   // HRR: group with len 0
    std::vector<std::string> alpn;
    std::string sni;
    size_t length = 0;
};
HelloInfo parse_hello(const std::vector<unsigned char>& msg);

// What the finished handshake actually used.
struct Negotiated {
    std::string version, cipher, group, peer_sig, own_sig;
    std::string peer_sig_iana;  // e.g. "ecdsa_secp256r1_sha256" (best effort)
};
Negotiated describe(SSL* ssl);
std::string to_string(const Negotiated& n, const Trace& t);

std::vector<std::string> split(const std::string& s, char sep);
std::string join(const std::vector<std::string>& v, const std::string& sep);

// Minimal "--name value" / "--flag" command-line parser.
class Args {
public:
    Args(int argc, char** argv) : tok_(argv + 1, argv + argc) {}
    bool flag(const std::string& name) const;
    std::string get(const std::string& name, const std::string& def = "") const;
    std::string get_any(const std::vector<std::string>& names, const std::string& def = "") const;
    std::vector<std::string> all(const std::string& name) const;

private:
    std::vector<std::string> tok_;
};

}  // namespace tlsf
