#include "file_writer.h"
#include <stdexcept>
#include <iostream>

FileWriter::FileWriter(
	const std::string& file_path) :
	output_file_(file_path)
{
	if (!output_file_) {
		throw std::runtime_error("Failed to open output file: " + file_path);
	}
}

FileWriter::~FileWriter() { }

bool FileWriter::Write(const std::string& message)
{
	output_file_ << message.c_str() << std::endl;
	output_file_.flush();
	return bool(output_file_);
}
