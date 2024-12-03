# Secure Banking Server-Client Application

This project implements a secure Server-Client application for basic banking operations, designed with TLS/SSL encryption to protect user data during transactions. The server and client can handle tasks like Account creation, Login, Balance checks, Deposits, and Withdrawals.

## Project Structure

-	Makefile: Compiles the Server and client code and generates SSL certificates automatically.
-	server.cpp: Contains the server logic for handling client requests and user account management.
-	client.cpp: Provides a client interface to interact with the server for various banking functions.
-	auth.txt / auth_backup.txt: Stores user data persistently, with periodic backups.
  
## Requirements

-	Ubuntu OS
-	OpenSSL Library: sudo apt update sudo apt install libssl-dev
-	C++ Compiler: GCC and C++17.
  
## Setup and Compilation

1. Directory Creation:
```
   mkdir -p src build/bin certs
   mv Bank_client.cpp src/
   mv Bank_Server.cpp src/
```
-   ![Project Structure](<Structure.jpg>)

2.	Compile the Project:
1.	Run the Makefile to compile both the server and client programs, as well as generate the necessary SSL certificates: make
   
2.	This will generate:
-	server and client binaries
-	server_cert.pem and server_key.pem for Server SSL communication
-	public_key.pem and private_key.pem for client-Server secure data handling

3. Running the Application
1.	Start the Server:
-	Run the server program with: ./bank
-	The server listens on localhost at port 8080 for client connections.

2.	Start the Client:
-	Open a new terminal session and run: ./atm
-	The client connects to the server on 127.0.0.1 (localhost) at port 8080.

## Error Handling
-	Logs errors and provides user feedback on all operations.
  
## Cleaning Up
- To remove generated binaries and certificates: make clean
  
## Note
Upon compilation, auth.txt and auth_backup.txt files are used to manage and backup user data. Ensure they are handled securely, especially in production.