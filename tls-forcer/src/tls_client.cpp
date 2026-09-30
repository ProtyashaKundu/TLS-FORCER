// tls_client.cpp - connect to a server and FORCE a key exchange / signature
//   ./tls_client --host example.com --port 443 --group X25519 --sigalg ed25519
/**
main()	Fills ClientConfig from flags, prints the menu, calls run_handshake(), then prints OK, NOT SENT (your OpenSSL refused) or FAILED (the server refused)
usage()	Prints the help text
*/

#include "client_core.hpp"
#include <iostream>

using namespace tlsf;

static void usage() 
{
    std::cerr <<
    R"(usage: tls_client --host H [--port P] [options]
  --group(s) LIST        key exchange groups, e.g. X25519 | P-256 | X25519MLKEM768
  --sigalg(s) LIST       signature schemes, e.g. ed25519 | ecdsa_secp256r1_sha256 | rsa_pss_rsae_sha256
  --ciphersuites LIST    TLS 1.3 suites, e.g. TLS_CHACHA20_POLY1305_SHA256
  --cipher-list LIST     TLS 1.2 suites, e.g. ECDHE-RSA-AES128-GCM-SHA256
  --tls12 | --tls13      pin the protocol version
  --sni NAME             SNI / name to verify (default: host)
  --cafile FILE          trust this CA (e.g. certs/ca.crt from gen_certs.sh)
  --insecure             skip certificate verification
  --get PATH             send "GET PATH" after the handshake and print the reply
  --provider NAME        load an OpenSSL provider (repeatable), e.g. oqsprovider
LIST is colon-separated. One entry = forced; several = offered in that order.
)";
}

int main(int argc, char** argv) 
{
    Args a(argc, argv);
    if (a.flag("--help") || a.flag("-h") || a.get("--host").empty()) {
        usage();
        return 2;
    }
    try {
        load_providers(a.all("--provider"));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 2;
    }

    ClientConfig c;
    c.host = a.get("--host");
    c.port = a.get("--port", "443");
    c.sni = a.get("--sni");
    c.groups = a.get_any({"--group", "--groups"});
    c.sigalgs = a.get_any({"--sigalg", "--sigalgs"});
    c.ciphersuites = a.get("--ciphersuites");
    c.cipher_list = a.get("--cipher-list");
    c.cafile = a.get("--cafile");
    c.verify = !a.flag("--insecure");
    if (a.flag("--tls12")) c.min_version = c.max_version = TLS1_2_VERSION;
    if (a.flag("--tls13")) c.min_version = c.max_version = TLS1_3_VERSION;
    std::string path = a.get("--get");
    if (!path.empty())
        c.request = "GET " + path + " HTTP/1.1\r\nHost: " + c.host + "\r\nConnection: close\r\n\r\n";

    auto show = [](const std::string& s) { return s.empty() ? std::string("(OpenSSL default)") : s; };
    std::cout << "ClientHello will offer:\n"
              << "  groups        : " << show(c.groups) << "\n"
              << "  sigalgs       : " << show(c.sigalgs) << "\n"
              << "  1.3 suites    : " << show(c.ciphersuites) << "\n"
              << "  1.2 suites    : " << show(c.cipher_list) << "\n\n";

    HandshakeResult r = run_handshake(c);
    if (!r.ok) {
        std::cout << (r.rejected_locally ? "NOT SENT" : "FAILED") << ": " << r.error << "\n";
        if (!r.rejected_locally)
            std::cout << "\nThe server refused everything we offered (or the network/cert failed).\n";
        return 1;
    }
    std::cout << "Handshake OK. Server chose:\n" << to_string(r.neg, r.trace);
    if (!r.response.empty()) std::cout << "\n--- server response ---\n" << r.response << "\n";
    return 0;
}
