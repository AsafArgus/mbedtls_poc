## variables
SRC_DIR = ./src
SRC_FILES = $(shell ls $(SRC_DIR)/*.cc)
PROGRAM_OBJS = $(SRC_FILES:.cc=.o)

PROGRAM_NAME = poc

.PHONY: mbedtls

## targets
all: $(PROGRAM_NAME)

$(PROGRAM_NAME): mbedtls $(PROGRAM_OBJS)
	$(CXX) $(CXXFLAGS) $(PROGRAM_CXXFLAGS) $(PROGRAM_OBJS) $(PROGRAM_LDFLAGS) $(LDFLAGS) -o $@

clean:
	-rm -f $(SRC_DIR)/*.o $(PROGRAM_NAME)
	make -C $(MBEDTLS_SRC_DIR) clean


PROGRAM_LDFLAGS = -pthread 			\
		-L./mbedtls/library	\
		-lmbedtls  			\
		-lmbedx509 			\
		-lmbedcrypto			\


PROGRAM_CXXFLAGS = $(WARNING_CFLAGS) \
	-I./mbedtls/include -D_FILE_OFFSET_BITS=64	\
	-I./src/include										\
	-std=c++11

$(SRC_DIR)/%.o:$(SRC_DIR)/%.cc
	$(CXX) $(CXXFLAGS) $(PROGRAM_CXXFLAGS) -c -o $@ $<


## mbedtls
MBEDTLS_SRC_DIR = mbedtls

mbedtls:
	git submodule init $(MBEDTLS_SRC_DIR)
	git submodule sync $(MBEDTLS_SRC_DIR)
	git submodule update --recursive $(MBEDTLS_SRC_DIR)
	
	# using mbedtls original Makefile
	+make -C $(MBEDTLS_SRC_DIR)

mbedtls_clean:
	make -C $(MBEDTLS_SRC_DIR) clean


## General

CXXWARNINGS = -Wextra -Wcast-align -Wshadow -Wpacked \
-Wall -Wcast-qual \
-Wdisabled-optimization \
-Werror -Wformat=2 \
-Wformat-nonliteral -Wformat-security  \
-Wformat-y2k \
-Wimport \
-Winit-self \
-Winline \
-Winvalid-pch   \
-Wmissing-field-initializers \
-Wmissing-format-attribute   \
-Wmissing-include-dirs \
-Wmissing-noreturn \
-Wpointer-arith \
-Wstack-protector \
-Wstrict-aliasing=2 \
-Wunreachable-code -Wunused \
-Wunused-parameter \
-Wvariadic-macros \
-Wwrite-strings

CXXFLAGS = $(CXXWARNINGS)


## Cross compilation
export CC = $(TOOLCHAIN)gcc
export CXX = $(TOOLCHAIN)g++
export AR = $(TOOLCHAIN)ar
export RANLIB = $(TOOLCHAIN)ranlib
export LD = $(TOOLCHAIN)ld

