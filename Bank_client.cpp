#include <iostream>
#include <string>
#include <cstring>      // For strerror
#include <sys/socket.h> // For socket functions
#include <arpa/inet.h>  // For inet_addr and htons
#include <unistd.h>     // For close()

using namespace std;

void handle_account_creation(const string& account, const string& initial_balance);
void handle_deposit(const string& account, const string& amount);
void handle_withdrawal(const string& account, const string& amount);
void handle_balance_check(const string& account);
void send_request(const string& request);
void print_error(const string& message);

int main(int argc, char* argv[]) {
    string account;
    string amount;
    string initial_balance;

    // Parse command-line options
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-a" && i + 1 < argc) {
            account = argv[++i];
        } else if (arg == "-n" && i + 1 < argc) {
            initial_balance = argv[++i];
        } else if (arg == "-d" && i + 1 < argc) {
            amount = argv[++i];
        } else if (arg == "-w" && i + 1 < argc) {
            amount = argv[++i];
        } else if (arg == "-g" && i + 1 < argc) {
            account = argv[++i];
        } else {
            cerr << "Usage: " << argv[0] << " [-a account_name] [-n initial_balance] [-d deposit_amount] [-w withdrawal_amount] [-g account_name]" << endl;
            return 255;
        }
    }

    // Perform actions based on parsed arguments
    if (!account.empty() && !initial_balance.empty()) {
        handle_account_creation(account, initial_balance);
    } else if (!account.empty() && !amount.empty()) {
        if (amount.find('.') != string::npos) {
            handle_deposit(account, amount);
        } else {
            handle_withdrawal(account, amount);
        }
    } else if (!account.empty()) {
        handle_balance_check(account);
    }

    return 0;
}

void handle_account_creation(const string& account, const string& initial_balance) {
    string request = "CREATE " + account + " " + initial_balance;
    send_request(request);
}

void handle_deposit(const string& account, const string& amount) {
    string request = "DEPOSIT " + account + " " + amount;
    send_request(request);
}

void handle_withdrawal(const string& account, const string& amount) {
    string request = "WITHDRAW " + account + " " + amount;
    send_request(request);
}

void handle_balance_check(const string& account) {
    string request = "BALANCE " + account;
    send_request(request);
}

void send_request(const string& request) {
    int clientSocket;
    struct sockaddr_in serverAddress;
    const char* message = request.c_str();

    // Create a socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        print_error("Socket creation failed");
        exit(1);
    }

    // Specify server address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        print_error("Connection failed");
        close(clientSocket);
        exit(1);
    }

    // Send data
    if (send(clientSocket, message, request.length(), 0) == -1) {
        print_error("Send failed");
        close(clientSocket);
        exit(1);
    }

    // Receive response
    char buffer[1024];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead == -1) {
        print_error("Receive failed");
        close(clientSocket);
        exit(1);
    }
    buffer[bytesRead] = '\0';  // Null-terminate the response
     //printing buffer and terminate it with "endl"
    cout << buffer << endl;

    // Cleanup
    close(clientSocket);
}

void print_error(const string& message) {
    cerr << message << ": " << strerror(errno) << endl;
}
