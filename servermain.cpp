#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sstream>

#define DEBUG

void print_error(const std::string &message) {
    std::cerr << "ERROR: " << message << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_error("Usage: ./server <hostname>:<port>");
        return 1;
    }

    // Dela upp värdnamn och port
    char *host = strtok(argv[1], ":");
    char *port_str = strtok(NULL, ":");

    if (!host || !port_str) {
        print_error("Invalid format for <hostname>:<port>");
        return 1;
    }

    int port = std::stoi(port_str);

#ifdef DEBUG
    std::cout << "Server listening on " << host << ":" << port << std::endl;
#endif

    // Skapa socket för servern
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("Unable to open socket");
        return 1;
    }

    struct sockaddr_in server_addr, client_addr;
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Lyssna på alla nätverksadresser
    server_addr.sin_port = htons(port);

    // Binda servern till en adress
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        print_error("Unable to bind to port");
        return 1;
    }

    listen(sockfd, 5);  // Vänta på klientanslutningar
    std::cout << "Server is ready, waiting for connections on port " << port << std::endl;

    while (true) {
        socklen_t client_len = sizeof(client_addr);
        int newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (newsockfd < 0) {
            print_error("Failed to accept connection");
            continue;
        }

        // Läs klientens operation
        char buffer[256];
        bzero(buffer, 256);
        int n = read(newsockfd, buffer, 255);
        if (n < 0) {
            print_error("Failed to read from client");
            continue;
        }

        std::string operation(buffer);  // Skapa en sträng från operationen
        std::string result_str = "OK (myresult=<result>)\n";

        // Exempel på att hantera operationer som add, sub, mul, div
        int v1, v2, result;
        std::stringstream ss(operation);
        std::string op;
        ss >> op >> v1 >> v2;

        if (op == "add") {
            result = v1 + v2;
        } else if (op == "sub") {
            result = v1 - v2;
        } else if (op == "mul") {
            result = v1 * v2;
        } else if (op == "div") {
            result = v1 / v2;
        } else {
            result_str = "ERROR: Invalid operation\n";
        }

        // Skicka tillbaka resultatet till klienten
        std::stringstream result_stream;
        result_stream << result;
        result_str.replace(result_str.find("<result>"), 8, result_stream.str());
        n = write(newsockfd, result_str.c_str(), result_str.length());

        if (n < 0) {
            print_error("Failed to send result to client");
            continue;
        }

        close(newsockfd);  // Stäng anslutningen när den är klar
    }

    close(sockfd);  // Stäng serverns socket
    return 0;
}
