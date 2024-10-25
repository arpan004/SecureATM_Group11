# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto

# Source files
CLIENT_SRC = Bank_client.cpp
SERVER_SRC = Bank_Server.cpp

# Output binaries
CLIENT_BIN = client
SERVER_BIN = server

# Certificate and key files
SERVER_CERT = server_cert.pem
SERVER_KEY = server_key.pem
CLIENT_CERT = client_cert.pem
CLIENT_KEY = client_key.pem
CA_CERT = ca_cert.pem
PUBLIC_KEY_FILE = public_key.pem
PRIVATE_KEY_FILE = private_key.pem

# Default target
all: $(CLIENT_BIN) $(SERVER_BIN) certs

# Compile client
$(CLIENT_BIN): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) $(CLIENT_SRC) -o $(CLIENT_BIN) $(LDFLAGS)

# Compile server
$(SERVER_BIN): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) $(SERVER_SRC) -o $(SERVER_BIN) $(LDFLAGS)

# Generate certificates and keys
certs: $(SERVER_CERT) $(SERVER_KEY) $(CLIENT_CERT) $(CLIENT_KEY) $(CA_CERT) $(PUBLIC_KEY_FILE) $(PRIVATE_KEY_FILE)

$(SERVER_CERT) $(SERVER_KEY):
	openssl req -x509 -newkey rsa:2048 -keyout $(SERVER_KEY) -out $(SERVER_CERT) -days 365 -nodes -subj "/CN=localhost"

$(CLIENT_CERT) $(CLIENT_KEY):
	openssl req -x509 -newkey rsa:2048 -keyout $(CLIENT_KEY) -out $(CLIENT_CERT) -days 365 -nodes -subj "/CN=localhost"

$(CA_CERT):
	openssl req -x509 -newkey rsa:2048 -keyout ca_key.pem -out $(CA_CERT) -days 365 -nodes -subj "/CN=CA"

$(PUBLIC_KEY_FILE) $(PRIVATE_KEY_FILE):
	openssl genpkey -algorithm RSA -out $(PRIVATE_KEY_FILE) -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in $(PRIVATE_KEY_FILE) -out $(PUBLIC_KEY_FILE)

# Clean up generated files
clean:
	rm -f $(CLIENT_BIN) $(SERVER_BIN) $(SERVER_CERT) $(SERVER_KEY) $(CLIENT_CERT) $(CLIENT_KEY) ca_key.pem $(CA_CERT) $(PUBLIC_KEY_FILE) $(PRIVATE_KEY_FILE)

# Phony targets
.PHONY: all clean certs