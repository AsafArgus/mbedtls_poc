#include <string>
#include <iostream>
#include <memory>
#include "ssl_client.h"
#include "file_writer.h"

int main() {
	try {
		std::string file_path = "output_file";
		std::string cert = "./ca.crt";
		std::string ip = "127.0.0.1";
		std::uint16_t port = 4444; //non existing port

		//constructor inits, and tries to connect.
		SslClient ssl_client(cert, ip, port);

		FileWriter file_writer(file_path);

		ssl_client.Send("hello");
		file_writer.Write("hello");

		std::cout << "Please check 'output_file'" << std::endl;
	}

	catch (const std::exception& e) {
		std::cout << "Exception: " << e.what() << std::endl;
	}

	return 0;
}
