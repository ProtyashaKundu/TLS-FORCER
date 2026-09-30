// tls_util.cpp - shared helpers for tls-forcer making handshake readable

/**
attach_trace() + msg_cb()	The wiretap. OpenSSL calls msg_cb for every message; it logs direction, type, size and time, and copies the raw hellos

HRR check in msg_cb + kHrrRandom	Detects a HelloRetryRequest: a ServerHello whose random field equals SHA-256("HelloRetryRequest"), found at byte offset 6

parse_hello() + parse_ext() + Reader	Reads the raw ClientHello and ServerHello byte by byte: suites, groups, key shares (and their sizes), signature schemes, versions, ALPN, SNI

describe()	Asks OpenSSL what was agreed: version, cipher, group, signature (works across OpenSSL versions)

group_id_name(), sigalg_id_name(), cipher_id_name(), ext_name(), handshake_type_name()	Translate wire numbers into names (0x001d → x25519)

is_grease()	Spots the fake GREASE values browsers insert. "Generate Random Extensions And Sustain Extensibility" (RFC 8701): these are fake, meaningless values that browsers deliberately put in their ClientHello, to make sure servers can cope with values they don't recognise.

load_providers()	Loads add-ons like oqsprovider for post-quantum algorithms

openssl_errors()	Turns OpenSSL's error queue into readable text

Args	Reads command-line flags like --host google.com
*/
#include "tls_util.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>

namespace tlsf {

std::string openssl_errors() 
{
    std::string out;
    char buf[256];
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof buf);
        if (!out.empty()) out += "; ";
        out += buf;
    }
    return out.empty() ? "(no OpenSSL error recorded)" : out;
}

static std::string hex16(uint16_t id) 
{
    std::ostringstream o;
    o << "0x" << std::hex << std::setw(4) << std::setfill('0') << id;
    return o.str();
}

bool is_grease(uint16_t id) 
{
    return (id & 0x0f0f) == 0x0a0a && (id >> 8) == (id & 0xff);
}

std::string group_id_name(uint16_t id) 
{
    static const std::map<uint16_t, const char*> names = {
        {0x0017, "secp256r1"},      {0x0018, "secp384r1"},
        {0x0019, "secp521r1"},      {0x001d, "x25519"},
        {0x001e, "x448"},           {0x0100, "ffdhe2048"},
        {0x0101, "ffdhe3072"},      {0x0102, "ffdhe4096"},
        {0x0103, "ffdhe6144"},      {0x0104, "ffdhe8192"},
        {0x0200, "MLKEM512"},       {0x0201, "MLKEM768"},
        {0x0202, "MLKEM1024"},      {0x11eb, "SecP256r1MLKEM768"},
        {0x11ec, "X25519MLKEM768"}, {0x11ed, "SecP384r1MLKEM1024"},
        {0x6399, "X25519Kyber768Draft00"},
    };
    if (is_grease(id)) return "GREASE";
    auto it = names.find(id);
    return it != names.end() ? it->second : hex16(id);
}

std::string sigalg_id_name(uint16_t id) 
{
    static const std::map<uint16_t, const char*> names = {
        {0x0201, "rsa_pkcs1_sha1"},         {0x0203, "ecdsa_sha1"},
        {0x0202, "dsa_sha1"},               {0x0301, "rsa_sha224"},
        {0x0302, "dsa_sha224"},             {0x0303, "ecdsa_sha224"},
        {0x0402, "dsa_sha256"},             {0x0502, "dsa_sha384"},
        {0x0602, "dsa_sha512"},
        {0x0401, "rsa_pkcs1_sha256"},       {0x0501, "rsa_pkcs1_sha384"},
        {0x0601, "rsa_pkcs1_sha512"},       {0x0403, "ecdsa_secp256r1_sha256"},
        {0x0503, "ecdsa_secp384r1_sha384"}, {0x0603, "ecdsa_secp521r1_sha512"},
        {0x0804, "rsa_pss_rsae_sha256"},    {0x0805, "rsa_pss_rsae_sha384"},
        {0x0806, "rsa_pss_rsae_sha512"},    {0x0807, "ed25519"},
        {0x0808, "ed448"},                  {0x0809, "rsa_pss_pss_sha256"},
        {0x080a, "rsa_pss_pss_sha384"},     {0x080b, "rsa_pss_pss_sha512"},
        {0x0904, "mldsa44"},                {0x0905, "mldsa65"},
        {0x0906, "mldsa87"},
    };
    if (is_grease(id)) return "GREASE";
    auto it = names.find(id);
    return it != names.end() ? it->second : hex16(id);
}

void load_providers(const std::vector<std::string>& names) {
    if (names.empty()) return;
    if (!OSSL_PROVIDER_load(nullptr, "default"))
        throw std::runtime_error("cannot load default provider: " + openssl_errors());
    for (const auto& n : names)
        if (!OSSL_PROVIDER_load(nullptr, n.c_str()))
            throw std::runtime_error("cannot load provider '" + n + "': " + openssl_errors());
}

// SHA-256("HelloRetryRequest")
static const unsigned char kHrrRandom[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
    0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
    0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

static void msg_cb(int write_p, int /*version*/, int content_type, const void* buf, size_t len, SSL* /*ssl*/, void* arg)
{
    if (len < 1) return;
    if (content_type != SSL3_RT_HANDSHAKE && content_type != SSL3_RT_CHANGE_CIPHER_SPEC &&
        content_type != SSL3_RT_ALERT)
        return;  // skip record headers / inner-content-type pseudo records
    auto* t = static_cast<Trace*>(arg);
    auto* p = static_cast<const unsigned char*>(buf);
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t->t0).count();

    int detail = 0;
    bool hrr = false;
    if (content_type == SSL3_RT_HANDSHAKE) {
        detail = p[0];
        if (p[0] == SSL3_MT_CLIENT_HELLO) t->client_hellos++;
        // Handshake header: type(1) length(3) legacy_version(2) random(32)
        if (p[0] == SSL3_MT_SERVER_HELLO && len >= 38 && std::memcmp(p + 6, kHrrRandom, 32) == 0)
            hrr = t->hrr = true;
        if (p[0] == SSL3_MT_CLIENT_HELLO || p[0] == SSL3_MT_SERVER_HELLO)
            t->hellos.emplace_back(p, p + len);
    } 
    else if (content_type == SSL3_RT_ALERT && len >= 2) 
    {
        detail = p[1];
    }
    t->events.push_back({write_p != 0, content_type, detail, hrr, len, ms});
}

std::string cipher_id_name(uint16_t id) 
{
    if (is_grease(id)) return "GREASE";
    if (id == 0x00ff) return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
    // SSL_CIPHER_find searches every suite OpenSSL knows, so a throwaway SSL works.
    static SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    static SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    unsigned char b[2] = {static_cast<unsigned char>(id >> 8), static_cast<unsigned char>(id & 0xff)};
    if (const SSL_CIPHER* c = ssl ? SSL_CIPHER_find(ssl, b) : nullptr)
        if (const char* n = SSL_CIPHER_standard_name(c)) return n;
    return hex16(id);
}

std::string ext_name(uint16_t id) 
{
    static const std::map<uint16_t, const char*> names = {
        {0, "server_name"},          {5, "status_request"},
        {10, "supported_groups"},    {11, "ec_point_formats"},
        {13, "signature_algorithms"},{16, "alpn"},
        {18, "signed_cert_timestamp"},{21, "padding"},
        {22, "encrypt_then_mac"},    {23, "extended_master_secret"},
        {27, "compress_certificate"},{35, "session_ticket"},
        {41, "pre_shared_key"},      {42, "early_data"},
        {43, "supported_versions"},  {44, "cookie"},
        {45, "psk_key_exchange_modes"},{49, "post_handshake_auth"},
        {50, "signature_algorithms_cert"},{51, "key_share"},
        {17513, "application_settings"},{65037, "encrypted_client_hello"},
        {65281, "renegotiation_info"},
    };
    if (is_grease(id)) return "GREASE";
    auto it = names.find(id);
    return it != names.end() ? it->second : std::to_string(id);
}

std::string handshake_type_name(int type, bool hrr) {
    switch (type) {
        case 1: return "ClientHello";
        case 2: return hrr ? "HelloRetryRequest" : "ServerHello";
        case 4: return "NewSessionTicket";
        case 8: return "EncryptedExtensions";
        case 11: return "Certificate";
        case 12: return "ServerKeyExchange";
        case 13: return "CertificateRequest";
        case 14: return "ServerHelloDone";
        case 15: return "CertificateVerify";
        case 16: return "ClientKeyExchange";
        case 20: return "Finished";
        case 22: return "CertificateStatus";
        case 24: return "KeyUpdate";
        default: return "Handshake(" + std::to_string(type) + ")";
    }
}

namespace 
{
	struct Reader 
	{
	    const unsigned char* p;
	    size_t n, i = 0;
	    bool need(size_t k) const
	    { 
	    	return i + k <= n; 
	    }
	    uint8_t u8() 
	    { 
	    	return p[i++]; 
	    }
	    uint16_t u16() 
	    { 
	    	uint16_t v = static_cast<uint16_t>((p[i] << 8) | p[i + 1]); i += 2; return v; 
	    }
	};

	void u16_list(Reader& e, std::vector<uint16_t>& out, bool one_byte_len) {
	    if (!e.need(one_byte_len ? 1 : 2)) return;
	    size_t len = one_byte_len ? e.u8() : e.u16();
	    size_t end = std::min(e.n, e.i + len);
	    while (e.i + 2 <= end) out.push_back(e.u16());
	}

	void parse_ext(HelloInfo& h, uint16_t type, Reader e) {
	    switch (type) 
	    {
		  case 0:  // server_name: list_len(2) name_type(1) name_len(2) name
		      if (e.need(5))
		       {
		          e.u16(); e.u8();
		          size_t l = e.u16();
		          if (e.need(l)) h.sni.assign(reinterpret_cast<const char*>(e.p + e.i), l);
			}
		      break;
		  case 10: u16_list(e, h.groups, false); break;
		  case 13: u16_list(e, h.sigalgs, false); break;
		  case 16:  // alpn: list_len(2) { len(1) proto }*
		      if (e.need(2)) 
		      {
		          size_t list_len = e.u16();
		          size_t end = std::min(e.n, e.i + list_len);
		          while (e.i < end) 
		          {
		              size_t l = e.u8();
		              if (e.i + l > end) break;
		              h.alpn.emplace_back(reinterpret_cast<const char*>(e.p + e.i), l);
		              e.i += l;
		          }
		      }
		      break;
		  case 43:
		      if (h.client) u16_list(e, h.versions, true);
		      else if (e.need(2)) h.versions.push_back(e.u16());
		      break;
		  case 51:
		      if (h.client) 
		      {  // list_len(2) { group(2) len(2) key }*
		          if (!e.need(2)) break;
		          size_t list_len = e.u16();
		          size_t end = std::min(e.n, e.i + list_len);
		          while (e.i + 4 <= end) {
		              uint16_t g = e.u16();
		              size_t l = e.u16();
		              h.key_shares.push_back({g, l});
		              e.i += l;
		          }
		      } 
		      else if (e.need(2)) 
		      {  // ServerHello: group(2) len(2) key; HRR: group(2)
		          uint16_t g = e.u16();
		          size_t l = e.need(2) ? e.u16() : 0;
		          h.key_shares.push_back({g, l});
		      }
		      break;
	    }
	}
	}  // namespace

	HelloInfo parse_hello(const std::vector<unsigned char>& m) 
	{
	    HelloInfo h;
	    h.length = m.size();
	    if (m.size() < 4 || (m[0] != 1 && m[0] != 2)) return h;
	    h.client = m[0] == 1;
	    size_t body = (static_cast<size_t>(m[1]) << 16) | (m[2] << 8) | m[3];
	    Reader r{m.data() + 4, std::min(body, m.size() - 4)};
	    if (!r.need(2 + 32 + 1)) return h;
	    r.i += 2;  // legacy_version
	    if (!h.client && std::memcmp(r.p + r.i, kHrrRandom, 32) == 0) h.hrr = true;
	    r.i += 32;
	    size_t sid = r.u8();
	    if (!r.need(sid)) return h;
	    r.i += sid;
	    if (h.client) {
		  if (!r.need(2)) return h;
		  size_t cl = r.u16();
		  if (!r.need(cl)) return h;
		  for (size_t k = 0; k + 1 < cl; k += 2)
		      h.suites.push_back(static_cast<uint16_t>((r.p[r.i + k] << 8) | r.p[r.i + k + 1]));
		  r.i += cl;
		  if (!r.need(1)) return h;
		  size_t comp = r.u8();
		  if (!r.need(comp)) return h;
		  r.i += comp;
	    } else {
		  if (!r.need(3)) return h;
		  h.suites.push_back(r.u16());
		  r.i += 1;  // compression
	    }
	    h.ok = true;
	    if (!r.need(2)) return h;
	    size_t ext_len = r.u16();
	    size_t end = std::min(r.n, r.i + ext_len);
	    while (r.i + 4 <= end) {
		  uint16_t t = r.u16();
		  size_t l = r.u16();
		  if (r.i + l > end) break;
		  h.extensions.push_back(t);
		  parse_ext(h, t, Reader{r.p + r.i, l});
		  r.i += l;
	    }
	    return h;
	}

	void attach_trace(SSL* ssl, Trace* trace) 
	{
	    SSL_set_msg_callback(ssl, msg_cb);
	    SSL_set_msg_callback_arg(ssl, trace);
	}

	static std::string nid_name(int nid)
	{
	    if (nid == NID_undef) return "unknown";
	    const char* sn = OBJ_nid2sn(nid);
	    return sn ? sn : "nid:" + std::to_string(nid);
	}

	static std::string sig_desc(SSL* s, bool peer) 
	{
	    int type = NID_undef, hash = NID_undef;
	    int ok = peer ? SSL_get_peer_signature_type_nid(s, &type)
		            : SSL_get_signature_type_nid(s, &type);
	    if (!ok) return "(none)";
	    if (peer) SSL_get_peer_signature_nid(s, &hash);
	    else SSL_get_signature_nid(s, &hash);
	    std::string r = type == EVP_PKEY_EC        ? "ECDSA"
		            : type == EVP_PKEY_RSA       ? "RSA-PKCS1"
		            : type == EVP_PKEY_RSA_PSS   ? "RSA-PSS"
		            : type == NID_rsassaPss      ? "RSA-PSS"
		            : type == EVP_PKEY_ED25519   ? "Ed25519"
		            : type == EVP_PKEY_ED448     ? "Ed448"
		                                         : nid_name(type);
	    // EdDSA and ML-DSA sign the message directly; there is no separate hash.
	    if (hash != NID_undef && type != EVP_PKEY_ED25519 && type != EVP_PKEY_ED448)
		  r += " + " + nid_name(hash);
	    return r;
	}

	Negotiated describe(SSL* s) 
	{
	    Negotiated n;
	    n.version = SSL_get_version(s);
	    n.cipher = SSL_CIPHER_standard_name(SSL_get_current_cipher(s));
	#if OPENSSL_VERSION_NUMBER >= 0x30200000L
	    const char* g = SSL_get0_group_name(s);
	    n.group = g ? g : "(none)";
	#else
	    int nid = SSL_get_negotiated_group(s);
	    if (nid == NID_undef) n.group = "(none)";
	    else if (nid & TLSEXT_nid_unknown) n.group = group_id_name(nid & 0xffff);
	    else n.group = nid_name(nid);
	#endif
	    n.peer_sig = sig_desc(s, true);
	    n.own_sig = sig_desc(s, false);

	    int type = NID_undef, hash = NID_undef;
	    if (SSL_get_peer_signature_type_nid(s, &type)) 
	    {
		  SSL_get_peer_signature_nid(s, &hash);
		  const char* h = hash == NID_sha256 ? "sha256" : hash == NID_sha384 ? "sha384"
		                : hash == NID_sha512 ? "sha512" : hash == NID_sha1 ? "sha1" : "";
		  if (type == EVP_PKEY_ED25519) n.peer_sig_iana = "ed25519";
		  else if (type == EVP_PKEY_ED448) n.peer_sig_iana = "ed448";
		  else if (type == EVP_PKEY_EC)
		      n.peer_sig_iana = hash == NID_sha256 ? "ecdsa_secp256r1_sha256"
		                      : hash == NID_sha384 ? "ecdsa_secp384r1_sha384"
		                      : hash == NID_sha512 ? "ecdsa_secp521r1_sha512" : "ecdsa_sha1";
		  else if (type == EVP_PKEY_RSA_PSS || type == NID_rsassaPss)
		      n.peer_sig_iana = std::string("rsa_pss_rsae_") + h;
		  else if (type == EVP_PKEY_RSA)
		      n.peer_sig_iana = std::string("rsa_pkcs1_") + h;
	    }
	    return n;
	}

	std::string to_string(const Negotiated& n, const Trace& t) 
	{
	    std::ostringstream o;
	    o << "  protocol      : " << n.version << "\n"
		<< "  cipher suite  : " << n.cipher << "\n"
		<< "  key exchange  : " << n.group << "\n"
		<< "  peer signed   : " << n.peer_sig << "\n";
	    if (n.own_sig != "(none)") o << "  we signed     : " << n.own_sig << "\n";
	    o
		<< "  HelloRetryReq : " << (t.hrr ? "YES (first key share was rejected)" : "no")
		<< "\n"
		<< "  ClientHellos  : " << t.client_hellos << "\n";
	    return o.str();
	}

	std::vector<std::string> split(const std::string& s, char sep) 
	{
	    std::vector<std::string> out;
	    std::string cur;
	    std::istringstream in(s);
	    while (std::getline(in, cur, sep))
		  if (!cur.empty()) out.push_back(cur);
	    return out;
	}

	std::string join(const std::vector<std::string>& v, const std::string& sep) 
	{
	    std::string out;
	    for (size_t i = 0; i < v.size(); ++i) out += (i ? sep : "") + v[i];
	    return out;
	}

	bool Args::flag(const std::string& name) const 
	{
	    for (const auto& t : tok_)
		  if (t == name) return true;
	    return false;
	}

	std::string Args::get(const std::string& name, const std::string& def) const 
	{
	    for (size_t i = 0; i + 1 < tok_.size(); ++i)
		  if (tok_[i] == name) return tok_[i + 1];
	    return def;
	}

	std::string Args::get_any(const std::vector<std::string>& names, const std::string& def) const 
	{
	    for (const auto& n : names) 
	    {
		  std::string v = get(n);
		  if (!v.empty()) return v;
	    }
	    return def;
	}

	std::vector<std::string> Args::all(const std::string& name) const 
	{
	    std::vector<std::string> out;
	    for (size_t i = 0; i + 1 < tok_.size(); ++i)
		  if (tok_[i] == name) out.push_back(tok_[i + 1]);
	    return out;
	}
}  // namespace tlsf
