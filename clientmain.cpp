#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <arpa/inet.h>  // För att hantera IPv4 och IPv6

#define DEBUG

using namespace std;

void print_error(const char *message) {
    fprintf(stderr, "ERROR: %s\n", message);
}

int main(int argc, char *argv[]) {
    // Kontrollera att användaren skickat rätt argument (hostname:port)
    if (argc != 2) {
        print_error("Usage: ./client <hostname>:<port>");
        return 1;
    }

    // Dela upp argumentet i värdnamn och port
    char delim[] = ":";
    char *Desthost = strtok(argv[1], delim);
    char *Destport = strtok(NULL, delim);

    // Om vi inte får en port eller värdnamn, skriv ut fel
    if (Desthost == NULL || Destport == NULL) {
        print_error("ERROR: Invalid input format. Expected <hostname>:<port>");
        return 1;
    }

    int port = atoi(Destport);  // Omvandla port till ett heltal

    if (port == 0) {
        print_error("ERROR: Invalid port number.");
        return 1;
    }

#ifdef DEBUG
    printf("Host: %s, and Port: %d\n", Desthost, port);
#endif

    // Skapa en socket för klienten
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("ERROR: Cannot open socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(Desthost);  // Konvertera IP-strängen till adress
    server_addr.sin_port = htons(port);  // Sätt porten till den angivna porten

    // Anslut till servern
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        print_error("ERROR: Cannot connect to server");
        return 1;
    }

    printf("Connected to %s:%d\n", Desthost, port);

    // Skicka begäran till servern (exempel: add 10 5)
    string operation = "add 10 5";  // Här kan du ändra operationen
    int n = write(sockfd, operation.c_str(), operation.length());
    if (n < 0) {
        print_error("ERROR: Failed to write to socket");
        return 1;
    }

    // Läs serverns svar
    char buffer[256];
    bzero(buffer, 256);
    n = read(sockfd, buffer, 255);
    if (n < 0) {
        print_error("ERROR: Failed to read from server");
        return 1;
    }

    // Skriv ut serverns svar
    printf("Server response: %s\n", buffer);

    close(sockfd);  // Stäng socketen när vi är klara
    return 0;
}
