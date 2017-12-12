#include <stdexcept>
#include <iostream>
#include <cstring>
#include "ssl_client.h"

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#else
#include <Winsock2.h>
#endif

SslClient::SslClient(
	const std::string& ca_certificate,
	const std::string& address,
	uint16_t port) :
	address_(address),
	port_(port)
{
	Init(ca_certificate);
}

SslClient::~SslClient()
{
	Close();
}

bool SslClient::Connect()
{
	std::cout << "trying to connect..." << std::endl;
	int ret = mbedtls_ssl_session_reset(&mbedtls_inner_objects_.ssl_);
	if (0 != ret) {
		std::cout<<"mbedtls_ssl_session_reset failed: " << ret << std::endl;
		return false;
	}

	mbedtls_ssl_conf_read_timeout(&mbedtls_inner_objects_.conf_, HANDSHAKE_TIMEOUT);

	ret = mbedtls_net_connect(&mbedtls_inner_objects_.server_fd_, address_.c_str(), std::to_string(port_).c_str(), MBEDTLS_NET_PROTO_TCP);
	if (0 != ret) {
		std::cout<<"mbedtls_net_connect failed: " << ret << std::endl;
		return false;
	}

	ret = mbedtls_ssl_handshake(&mbedtls_inner_objects_.ssl_);
	if (0 != ret) {
		// we use a blocking socket, so MBEDTLS_ERR_SSL_WANT_READ and MBEDTLS_ERR_SSL_WANT_WRITE are not suppose to happen.
		std::cout<<"mbedtls_ssl_handshake failed: " << ret << std::endl;
		return false;
	}

	ret = mbedtls_ssl_get_verify_result(&mbedtls_inner_objects_.ssl_);
	if (0 != ret) {
		std::cout<<"mbedtls_ssl_get_verify_result failed: " << ret << std::endl;
		return false;
	}

	mbedtls_ssl_conf_read_timeout(&mbedtls_inner_objects_.conf_, READ_CONNECTION_TIMEOUT);
	std::cout<<"Connected to " << address_ << ":" << port_ << std::endl;

	//struct timeval tv;
	//tv.tv_sec =  WRITE_CONNECTION_TIMEOUT / 1000;
	//tv.tv_usec = (WRITE_CONNECTION_TIMEOUT % 1000) * 1000;
	//if (setsockopt(mbedtls_inner_objects_.server_fd_.fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(struct timeval)) != 0) {
	//	std::cout<<"Could not set write timeout strerr " << std::string(std::strerror(errno)) << std::endl;
	//	return false;
	//}

	return true;
}

bool SslClient::Send(const std::string &message)
{
	const uint8_t * buffer = reinterpret_cast<const uint8_t *>(message.c_str());
	const size_t buffer_size = message.size();

	if (!CheckConnection()) {
		//if not connected - try to reconnect
		if (!Connect()) {
			return false;
		}
	}

	// Connected!
	uint32_t total_bytes_sent = 0;
	std::cout << "sending " << buffer_size << " bytes" << std::endl;
	while (total_bytes_sent < buffer_size) {
		int ret = mbedtls_ssl_write(&mbedtls_inner_objects_.ssl_, buffer + total_bytes_sent, buffer_size - total_bytes_sent);
		if (0 >= ret) {
			// Failed to send, reset the connection.
			mbedtls_ssl_session_reset(&mbedtls_inner_objects_.ssl_);
			std::cout<<"mbedtls_ssl_write failed: " << ret << std::endl;
			return false;
		}

		// ret is positive
		total_bytes_sent += static_cast<uint32_t>(ret);
	}

	return true;
}

bool SslClient::CheckConnection() {
	unsigned char c;
	int ret = mbedtls_ssl_read(&mbedtls_inner_objects_.ssl_, &c, sizeof(c));

	return (0 < ret || MBEDTLS_ERR_SSL_TIMEOUT == ret);
}

void SslClient::Init(const std::string& ca_certificate)
{
	mbedtls_net_init(&mbedtls_inner_objects_.server_fd_);
	mbedtls_ssl_init(&mbedtls_inner_objects_.ssl_);
	mbedtls_ssl_config_init(&mbedtls_inner_objects_.conf_);
	mbedtls_x509_crt_init(&mbedtls_inner_objects_.cacert_);
	mbedtls_x509_crt_init(&mbedtls_inner_objects_.clicert_);
	mbedtls_pk_init(&mbedtls_inner_objects_.pkey_);
	mbedtls_ctr_drbg_init(&mbedtls_inner_objects_.ctr_drbg_);
	mbedtls_entropy_init(&mbedtls_inner_objects_.entropy_);

	int ret = mbedtls_ctr_drbg_seed(
		&mbedtls_inner_objects_.ctr_drbg_,
		mbedtls_entropy_func,
		&mbedtls_inner_objects_.entropy_,
		reinterpret_cast<const unsigned char*>(PERSONAL_DATA.c_str()),
		PERSONAL_DATA.size());
	if (0 != ret) {
		throw std::runtime_error("mbedtls_ctr_drbg_seed failed: " + std::to_string(ret));
	}

	ret = mbedtls_x509_crt_parse_file(&mbedtls_inner_objects_.cacert_, ca_certificate.c_str());
	if (0 != ret) {
		throw std::runtime_error("mbedtls_x509_crt_parse_file failed: " + std::to_string(ret));
	}

	ret = mbedtls_ssl_config_defaults(&mbedtls_inner_objects_.conf_,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (0 != ret) {
		throw std::runtime_error("mbedtls_ssl_config_defaults failed: " + std::to_string(ret));
	}

	// force verification
	mbedtls_ssl_conf_authmode(&mbedtls_inner_objects_.conf_, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&mbedtls_inner_objects_.conf_, &mbedtls_inner_objects_.cacert_, NULL);

	mbedtls_ssl_conf_rng(&mbedtls_inner_objects_.conf_, mbedtls_ctr_drbg_random, &mbedtls_inner_objects_.ctr_drbg_);

	ret = mbedtls_ssl_setup(&mbedtls_inner_objects_.ssl_, &mbedtls_inner_objects_.conf_);
	if (0 != ret) {
		throw std::runtime_error("mbedtls_ssl_setup failed: " + std::to_string(ret));
	}

	mbedtls_ssl_set_bio(&mbedtls_inner_objects_.ssl_, &mbedtls_inner_objects_.server_fd_, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
	Connect();
}

void SslClient::Close()
{
	mbedtls_ssl_close_notify(&mbedtls_inner_objects_.ssl_);

	mbedtls_net_free(&mbedtls_inner_objects_.server_fd_);
	mbedtls_x509_crt_free(&mbedtls_inner_objects_.cacert_);
	mbedtls_ssl_free(&mbedtls_inner_objects_.ssl_);
	mbedtls_ssl_config_free(&mbedtls_inner_objects_.conf_);
	mbedtls_ctr_drbg_free(&mbedtls_inner_objects_.ctr_drbg_);
	mbedtls_entropy_free(&mbedtls_inner_objects_.entropy_);
}