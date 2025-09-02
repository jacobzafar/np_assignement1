#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#define DEBUG

void print_error(const std::string &message) {
    std::cerr << "ERROR: " << message << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_error("Usage: ./client <hostname>:<port>");
        return 1;
    }

    // Delar upp hostname och port från argumentet
    char *host = strtok(argv[1], ":");
    char *port_str = strtok(NULL, ":");

    if (!host || !port_str) {
        print_error("Invalid format for <hostname>:<port>");
        return 1;
    }

    int port = std::stoi(port_str);

#ifdef DEBUG
    std::cout << "Connecting to host: " << host << " on port: " << port << std::endl;
#endif

    // Skapa en socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("Unable to create socket");
        return 1;
    }

    // Resolve hostname to IP address
    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
        print_error("No such host");
        close(sockfd);
        return 1;
    }

    struct sockaddr_in server_addr;
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);

    // Anslut till servern
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        print_error("Unable to connect to server");
        close(sockfd);
        return 1;
    }

    // Skicka en exempeloperation till servern (ex. add 10 5)
    std::string operation = "add 10 5";
    int n = write(sockfd, operation.c_str(), operation.length());
    if (n < 0) {
        print_error("Failed to send operation to server");
        close(sockfd);
        return 1;
    }

    // Läs resultat från servern
    char buffer[256];
    bzero(buffer, 256);
    n = read(sockfd, buffer, 255);
    if (n < 0) {
        print_error("Failed to read from server");
        close(sockfd);
        return 1;
    }

    std::cout << "Server response: " << buffer << std::endl;

    close(sockfd);
    return 0;
}
