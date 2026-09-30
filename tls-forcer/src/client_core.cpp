// client_core.cpp - one TLS handshake with a restricted ("forced") offer

/**
ClientConfig	The order form: host, port, and the menu lists (groups, sigalgs, ciphersuites, cipher_list), versions, and whether to verify the certificate

HandshakeResult	The receipt: ok, rejected_locally, error, what was agreed (neg), and the message log (trace)

apply_offer()	Where forcing happens. Writes your lists into OpenSSL with SSL_CTX_set1_groups_list, SSL_CTX_set1_sigalgs_list, SSL_CTX_set_ciphersuites and SSL_CTX_set_cipher_list. One item means forced

run_handshake()	Does one full handshake: create the context, apply the offer, set up certificate checks, connect over TCP, set SNI, attach the wiretap, call SSL_connect(), then describe() the result
*/

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <memory>

namespace tlsf 
{

	namespace 
	{
	using CtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
	using SslPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;

	bool is_ip_literal(const std::string& h) {
	    unsigned char buf[16];
	    return inet_pton(AF_INET, h.c_str(), buf) == 1 || inet_pton(AF_INET6, h.c_str(), buf) == 1;
	}
}

std::string apply_offer(SSL_CTX* ctx, const ClientConfig& c) 
{
    auto reject = [](const std::string& what) 
    {
        return "local OpenSSL does not support " + what + ": " + openssl_errors();
    };
    if (c.min_version && !SSL_CTX_set_min_proto_version(ctx, c.min_version))
        return reject("that minimum version");
    if (c.max_version && !SSL_CTX_set_max_proto_version(ctx, c.max_version))
        return reject("that maximum version");

    // ---- The forcing happens here----
    // supported_groups + key_share
    if (!c.groups.empty() && !SSL_CTX_set1_groups_list(ctx, c.groups.c_str()))
        return reject("groups '" + c.groups + "'");
    // signature_algorithms
    if (!c.sigalgs.empty() && !SSL_CTX_set1_sigalgs_list(ctx, c.sigalgs.c_str()))
        return reject("sigalgs '" + c.sigalgs + "'");
    // cipher_suites (TLS 1.3 AEAD+hash)
    if (!c.ciphersuites.empty() && !SSL_CTX_set_ciphersuites(ctx, c.ciphersuites.c_str()))
        return reject("TLS 1.3 ciphersuites '" + c.ciphersuites + "'");
    // cipher_suites (TLS 1.2: KE + auth + cipher + MAC bundled in one name)
    if (!c.cipher_list.empty() && !SSL_CTX_set_cipher_list(ctx, c.cipher_list.c_str()))
        return reject("TLS 1.2 cipher list '" + c.cipher_list + "'");
    return "";
}

HandshakeResult run_handshake(const ClientConfig& c) 
{
    HandshakeResult r;
    ERR_clear_error();

    CtxPtr ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!ctx) {
        r.error = "SSL_CTX_new: " + openssl_errors();
        return r;
    }

    std::string err = apply_offer(ctx.get(), c);
    if (!err.empty()) {
        r.rejected_locally = true;
        r.error = err;
        return r;
    }

    if (c.verify) {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        int ok = c.cafile.empty()
                     ? SSL_CTX_set_default_verify_paths(ctx.get())
                     : SSL_CTX_load_verify_locations(ctx.get(), c.cafile.c_str(), nullptr);
        if (!ok) {
            r.error = "cannot load trust store: " + openssl_errors();
            return r;
        }
    }

    BIO* bio = BIO_new_connect((c.host + ":" + c.port).c_str());
    if (!bio || BIO_do_connect(bio) <= 0) 
    {
        r.error = "TCP connect to " + c.host + ":" + c.port + " failed: " + openssl_errors();
        BIO_free_all(bio);
        return r;
    }

    SslPtr ssl(SSL_new(ctx.get()), SSL_free);
    SSL_set_bio(ssl.get(), bio, bio);  

    const std::string name = c.sni.empty() ? c.host : c.sni;
    if (!is_ip_literal(name)) SSL_set_tlsext_host_name(ssl.get(), name.c_str());
    if (c.verify) 
    {
        if (is_ip_literal(name)) X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()), name.c_str());
        else SSL_set1_host(ssl.get(), name.c_str());
    }

    attach_trace(ssl.get(), &r.trace);

    if (SSL_connect(ssl.get()) != 1) 
    {
        r.error = "handshake failed: " + openssl_errors();
        long v = SSL_get_verify_result(ssl.get());
        if (v != X509_V_OK)
            r.error += std::string(" [certificate: ") + X509_verify_cert_error_string(v) + "]";
        return r;
    }

    r.ok = true;
    r.neg = describe(ssl.get());

    if (!c.request.empty())
    {
        SSL_write(ssl.get(), c.request.data(), static_cast<int>(c.request.size()));
        char buf[4096];
        int n;
        while ((n = SSL_read(ssl.get(), buf, sizeof buf)) > 0) r.response.append(buf, n);
    }
    SSL_shutdown(ssl.get());
    return r;
}

}  // namespace tlsf
