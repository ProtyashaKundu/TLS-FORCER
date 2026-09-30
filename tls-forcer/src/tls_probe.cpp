// tls_probe.cpp - map which key exchanges / signatures / suites a server accepts
//   ./tls_probe --host example.com --port 443
//
// For each candidate it runs one handshake offering ONLY that candidate (everything else left at OpenSSL defaults). Then it offers the same list in two orders to find out whose preference the server follows.

/**
base_config()	A starting order form (verification off, version pinned)
probe_axis()	The loop: for each group, signature or suite, force only that one and print YES / NO / not supported
preference_test()	Offers A,B then B,A. Same pick both times means the server decides
set_axis(), chosen()	Put an item in the right menu slot, and read back what was picked
*/
#include "client_core.hpp"
#include <iomanip>
#include <iostream>

using namespace tlsf;

namespace 
{

	const char* kDefaultGroups =
	    "X25519:X448:P-256:P-384:P-521:ffdhe2048:ffdhe3072:"
	    "X25519MLKEM768:SecP256r1MLKEM768:MLKEM512:MLKEM768:MLKEM1024";
	const char* kDefaultSigalgs =
	    "ed25519:ed448:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
	    "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_pss_sha256:rsa_pkcs1_sha256:"
	    "mldsa44:mldsa65:mldsa87";
	const char* kDefaultSuites13 =
	    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

	enum class Axis { Group, Sigalg, Suite };

	ClientConfig base_config(const Args& a) 
	{
	    ClientConfig c;
	    c.host = a.get("--host");
	    c.port = a.get("--port", "443");
	    c.sni = a.get("--sni");
	    c.verify = false;  // we care about negotiation, not trust
	    c.min_version = c.max_version = a.flag("--tls12") ? TLS1_2_VERSION : TLS1_3_VERSION;
	    return c;
	}

	void set_axis(ClientConfig& c, Axis axis, const std::string& v) 
	{
	    if (axis == Axis::Group) c.groups = v;
	    if (axis == Axis::Sigalg) c.sigalgs = v;
	    if (axis == Axis::Suite) c.ciphersuites = v;
	}

	std::string chosen(const HandshakeResult& r, Axis axis) 
	{
	    if (axis == Axis::Group) return r.neg.group;
	    if (axis == Axis::Sigalg) return r.neg.peer_sig;
	    return r.neg.cipher;
	}

	void probe_axis(const Args& a, Axis axis, const std::string& title, const std::string& list)
	{
	    std::cout << "\n== " << title << " (offering one at a time) ==\n";
	    for (const auto& item : split(list, ':')) 
	    {
		  ClientConfig c = base_config(a);
		  set_axis(c, axis, item);
		  HandshakeResult r = run_handshake(c);
		  std::cout << "  " << std::left << std::setw(30) << item;
		  if (r.rejected_locally) std::cout << "--    not supported by local OpenSSL\n";
		  else if (!r.ok) std::cout << "NO    server refused\n";
		  else
		      std::cout << "YES   " << chosen(r, axis) << (r.trace.hrr ? "  [HRR]" : "") << "\n";
	    }
	}

	// Offer A:B, then B:A. Same answer both times => server enforces its own order.
	void preference_test(const Args& a, Axis axis, const std::string& title, const std::string& x, const std::string& y) 
	{
	    ClientConfig c1 = base_config(a), c2 = base_config(a);
	    set_axis(c1, axis, x + ":" + y);
	    set_axis(c2, axis, y + ":" + x);
	    HandshakeResult r1 = run_handshake(c1), r2 = run_handshake(c2);
	    std::cout << "  " << std::left << std::setw(14) << title;
	    if (!r1.ok || !r2.ok) 
	    {
		  std::cout << "inconclusive (server must accept both " << x << " and " << y << ")\n";
		  return;
	    }
	    std::string p1 = chosen(r1, axis), p2 = chosen(r2, axis);
	    std::cout << x << ":" << y << " -> " << p1 << "   |   " << y << ":" << x << " -> " << p2
		        << "   => " << (p1 == p2 ? "SERVER preference" : "CLIENT preference") << "\n";
	}

}  // namespace

int main(int argc, char** argv) {
    Args a(argc, argv);
    if (a.get("--host").empty()) {
        std::cerr << "usage: tls_probe --host H [--port P] [--tls12] [--provider NAME]\n"
                     "                 [--groups LIST] [--sigalgs LIST] [--ciphersuites LIST]\n"
                     "                 [--pref-groups A:B] [--pref-suites A:B]\n";
        return 2;
    }
    try {
        load_providers(a.all("--provider"));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }

    // Baseline: what does the server pick when we offer OpenSSL's defaults?
    HandshakeResult base = run_handshake(base_config(a));
    std::cout << "Target " << a.get("--host") << ":" << a.get("--port", "443") << "\n";
    if (!base.ok) {
        std::cout << "Baseline handshake failed: " << base.error << "\n";
        return 1;
    }
    std::cout << "\n== Baseline (OpenSSL default offer) ==\n" << to_string(base.neg, base.trace);

    probe_axis(a, Axis::Group, "Key exchange groups", a.get("--groups", kDefaultGroups));
    probe_axis(a, Axis::Sigalg, "Signature schemes", a.get("--sigalgs", kDefaultSigalgs));
    if (!a.flag("--tls12"))
        probe_axis(a, Axis::Suite, "TLS 1.3 cipher suites", a.get("--ciphersuites", kDefaultSuites13));

    std::cout << "\n== Whose preference wins? ==\n";
    auto pg = split(a.get("--pref-groups", "X25519:P-256"), ':');
    auto ps = split(a.get("--pref-suites", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"), ':');
    if (pg.size() == 2) preference_test(a, Axis::Group, "groups", pg[0], pg[1]);
    if (ps.size() == 2 && !a.flag("--tls12")) preference_test(a, Axis::Suite, "suites", ps[0], ps[1]);
    std::cout << "  (group order also decides which key share is sent, so a group\n"
                 "   result can reflect 'server accepted the share it got'.)\n";
    return 0;
}
