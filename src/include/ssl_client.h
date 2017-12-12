#ifndef SSL_CLIENT
#define SSL_CLIENT

#include <string>
#include <vector>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"


// An implementation of client ssl socket. It uses the `mbedtls` library.
class SslClient{
private:
	// private struct of all the required mbedtls inner structures.
	struct MbedtlsInnerStructures {
		mbedtls_entropy_context entropy_;
		mbedtls_ctr_drbg_context ctr_drbg_;
		mbedtls_ssl_context ssl_;
		mbedtls_ssl_config conf_;
		mbedtls_x509_crt cacert_;
		mbedtls_x509_crt clicert_;
		mbedtls_pk_context pkey_;
		mbedtls_net_context server_fd_;
	};

public:
	// C'tor
	SslClient(const std::string& ca_certificate,
	        const std::string& address,
	        uint16_t port);

	// D'tor
	virtual ~SslClient();

	// Sends the given buffer to the server.
	// Returns true on success
	bool Send(const std::string &message);

private:
	// prohibit copy c'tor and assignment operator.
	SslClient(const SslClient& rhs);
	SslClient& operator=(const SslClient& rhs);


	// return true if read operations succeeded, or timed out.
	// otherwise (e.g EOF) - connection is closed, or there was an error;
	bool CheckConnection();

	// Connects to the server, and performs handshake.
	// Returns true on success
	bool Connect();

	// Inits all the inner structures.
	// Throws in case of an error.
	void Init(const std::string& ca_certificate);

	// Close the connection, and free all the inner structures.
	// Throws in case of an error.
	void Close();

	// Class members
	MbedtlsInnerStructures mbedtls_inner_objects_;

	const std::string address_;
	const uint16_t port_;


	// in milliseconds
	static const uint32_t HANDSHAKE_TIMEOUT = 1000;
	static const uint32_t READ_CONNECTION_TIMEOUT = 10;
	static const uint32_t WRITE_CONNECTION_TIMEOUT = 1000;

	// Personal data - in order to make the entropy as unique as possible
	const std::string PERSONAL_DATA = "ThisIsSomePersonalDataI<3U";
};


#endif // SSL_CLIENT
