// client_core.hpp - one TLS handshake with a restricted ("forced") offer
#pragma once
#include "tls_util.hpp"
#include <string>

namespace tlsf 
{
	struct ClientConfig 
	{
	    std::string host = "localhost";
	    std::string port = "4433";
	    std::string sni;           // defaults to host
	    // Empty string = OpenSSL default list. A single entry = forced choice.
	    std::string groups;        // key exchange, e.g. "X25519" or "X25519:P-256"
	    std::string sigalgs;       // e.g. "ed25519" or "ecdsa_secp256r1_sha256"
	    std::string ciphersuites;  // TLS 1.3 suites, e.g. "TLS_AES_256_GCM_SHA384"
	    std::string cipher_list;   // TLS 1.2 suites, e.g. "ECDHE-ECDSA-AES128-GCM-SHA256"
	    int min_version = 0;       // TLS1_2_VERSION, TLS1_3_VERSION, or 0
	    int max_version = 0;
	    bool verify = true;
	    std::string cafile;
	    std::string request;       // bytes to send after the handshake (optional)
	};

	struct HandshakeResult
	{
	    bool ok = false;
	    bool rejected_locally = false; 
	    std::string error;
	    Negotiated neg;
	    Trace trace;
	    std::string response;
	};

	HandshakeResult run_handshake(const ClientConfig& cfg);
	// Applies versions/groups/sigalgs/suites from cfg to ctx.
	// Returns "" on success, otherwise why the local OpenSSL refused.
	std::string apply_offer(SSL_CTX* ctx, const ClientConfig& cfg);

}  // namespace tlsf
