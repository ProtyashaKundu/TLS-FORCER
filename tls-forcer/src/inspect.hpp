// inspect.hpp - one fully instrumented TLS handshake (for the live dashboard)
#pragma once

#include "client_core.hpp"

#include <string>
#include <vector>

namespace tlsf 
{

	struct InspectOptions 
	{
	    std::vector<std::string> alpn{"h2", "http/1.1"};  // offer like a browser
	    bool wait_for_tickets = true;  // linger briefly to catch NewSessionTicket
	    int timeout_ms = 6000;
	};

	struct CertInfo 
	{
	    std::string subject, issuer, key, sigalg, not_before, not_after;
	    std::vector<std::string> sans;  // first few DNS names
	    size_t san_total = 0;
	};

	struct InspectResult 
	{
	    bool ok = false;
	    bool rejected_locally = false;
	    std::string error;
	    std::string host, port, ip;
	    double dns_ms = 0, tcp_ms = 0, tls_ms = 0;
	    Negotiated neg;
	    std::string alpn;
	    Trace trace;
	    std::vector<HelloInfo> hellos;  // parsed from trace.hellos
	    std::vector<CertInfo> chain;
	    bool verify_ok = false;
	    std::string verify;
	    ClientConfig cfg;
	};

	// Never verifies-and-aborts: the certificate verdict is recorded instead,
	// so a failing chain is still visible on the dashboard.
	InspectResult inspect(const ClientConfig& cfg, const InspectOptions& opt = {});
	std::string to_json(const InspectResult& r);

}  // namespace tlsf
