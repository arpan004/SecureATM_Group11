# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -Wall -Wextra -pedantic

# OpenSSL flags
OPENSSL_FLAGS = -lssl -lcrypto -lsqlite3 -pthread

# Executables
ATM = atm
BANK = bank

# Source files
ATM_SRC = Bank_client.cpp
BANK_SRC = Bank_Server.cpp

# Default target
all: $(ATM) $(BANK)

# ATM executable
$(ATM): $(ATM_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(OPENSSL_FLAGS)

# Bank executable
$(BANK): $(BANK_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(OPENSSL_FLAGS)

# Clean target
clean:
	rm -f $(ATM) $(BANK)

# Phony targets
.PHONY: all clean