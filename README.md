Secure Banking Server-Client Application
This project implements a secure server-client application for basic banking operations, designed with TLS/SSL encryption to protect user data during transactions. The server and client can handle tasks like account creation, login, balance checks, deposits, and withdrawals.
Features
•	Automatic SSL Certificate Generation: The Makefile generates SSL/TLS certificates for secure communication automatically.
•	RSA and AES Encryption: RSA public-key encryption is used for sensitive data transmission, while AES provides an additional layer of security for stored data.
•	User Authentication and Session Management: Supports account creation, login, and secure session handling with session tokens.
•	Data Persistence and Backups: User information is stored securely, with automatic backups after every session.
Project Structure
•	Makefile: Compiles the server and client code and generates SSL certificates automatically.
•	server.cpp: Contains the server logic for handling client requests and user account management.
•	client.cpp: Provides a client interface to interact with the server for various banking functions.
•	auth.txt / auth_backup.txt: Stores user data persistently, with periodic backups.
Requirements
•	Ubuntu OS
•	OpenSSL Library: Install with:
sudo apt update
sudo apt install libssl-dev
•	C++ Compiler: GCC or a similar compiler supporting C++11 or higher.
Setup and Compilation
1.	Compile the Project:
o	Run the Makefile to compile both the server and client programs, as well as generate the necessary SSL certificates:
make
o	This will generate:
	server and client binaries
	server_cert.pem and server_key.pem for server SSL communication
	public_key.pem and private_key.pem for client-server secure data handling
Running the Application
1.	Start the Server:
o	Run the server program with:
./server
o	The server listens on localhost at port 8080 for client connections.
2.	Start the Client:
o	Open a new terminal session and run:
./client
o	The client connects to the server on 127.0.0.1 (localhost) at port 8080.
Client Operations
The client provides the following interactive commands:
1.	Create Account:
o	Prompts for a username, password, and initial balance.
2.	Login:
o	Requests username, password, card ID, and account number for verification.
3.	Transaction Options:
o	Check Balance: Shows the current account balance.
o	Deposit: Allows deposits to the account.
o	Withdraw: Enables withdrawals within balance limits.
o	Logout: Ends the session securely.

Client Operation Requirements:
•	Username Requirements
Validation: Usernames must be 3-20 characters long and can only include alphanumeric characters and underscores (_).
Limitation: Non-alphanumeric or special characters (except _) are not allowed, which might restrict some users who prefer symbols in their usernames.
•	Amount (Initial Deposit, Withdrawals, and Deposits)
Validation: Amounts must be positive and cannot exceed 1,000,000. An invalid amount will result in an error response.
Limit: Defined arbitrarily with amount > 0 && amount <= 1000000 for both deposits and withdrawals, which restricts large transactions.
Account Balance Check: Withdrawals are limited to the available balance, preventing overdrafts.
Security
•	RSA Encryption: Secures sensitive data transmission.
•	AES Encryption: Protects stored passwords and financial data.
•	Session Tokens: Ensures secure and verified client sessions.
•	Backup Creation: After every session, user data is backed up for data recovery.
Error Handling
•	Logs errors and provides user feedback on all operations.
Cleaning Up
To remove generated binaries and certificates:
make clean
Note
Upon compilation, auth.txt and auth_backup.txt files are used to manage and backup user data. Ensure they are handled securely, especially in production.

