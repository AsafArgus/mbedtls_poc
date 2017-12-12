#ifndef FILE_WRITER
#define FILE_WRITER

#include <string>
#include <fstream>
#include <mutex>

// An implementation of a file writer - writes the log messages to a file on the disk.
// This class is thread-safe.
class FileWriter {

public:
	// C'tor
	FileWriter(const std::string& file_path);

	// D'tor
	virtual ~FileWriter();

	// Writes the message to the file
	// Returns true on success
	virtual bool Write(const std::string& message);

private:
	// prohibit copy c'tor and assignment operator.
	FileWriter(const FileWriter& rhs);
	FileWriter& operator=(const FileWriter& rhs);

	std::ofstream output_file_;
};


#endif // FILE_WRITER
