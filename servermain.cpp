#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

// För att få stöd för de funktioner vi använder
#include "calcLib.h"

#define DEBUG

using namespace std;

void print_error(const char *message) {
    fprintf(stderr, "ERROR: %s\n", message);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_error("Usage: ./server <hostname>:<port>");
        return 1;
    }

    char delim[] = ":";
    char *Desthost = NULL;
    char *Destport = NULL;

    // Kollar om användaren har angett rätt format (hostname:port)
    if (strchr(argv[1], ':') == NULL) {
        print_error("ERROR: Invalid format, must be <hostname>:<port>");
        return 1;
    }

    // Dela upp strängen i host och port
    Desthost = strtok(argv[1], delim);
    Destport = strtok(NULL, delim);

    // Kontrollera att både host och port har delats upp korrekt
    if (Desthost == NULL || Destport == NULL) {
        print_error("ERROR: Invalid format, missing host or port");
        return 1;
    }

    // Konverterar portnumret från en sträng till ett heltal
    int port = atoi(Destport);

    // Debugutskrift, visar vilken host och port som angivits
    #ifdef DEBUG
    printf("Host: %s, and Port: %d\n", Desthost, port);
    #endif

    // Skapa socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("ERROR: Cannot open socket");
        return 1;
    }

    // Förbereda serverns adress
    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Binda socketen till adressen
    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        print_error("ERROR: Cannot bind to socket");
        return 1;
    }

    // Vänta på anslutningar
    listen(sockfd, 5);
    printf("Server is listening on port %d...\n", port);

    // Loopa för att acceptera inkommande anslutningar
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &client_len);
        if (newsockfd < 0) {
            print_error("ERROR: Failed to accept connection");
            continue;
        }

        // Efter att en anslutning accepteras, här kan vi läsa och skriva data till klienten
        printf("Connection accepted!\n");

        // För nu kan vi stänga klientanslutningen (kan utvecklas vidare för att läsa/skicka data)
        close(newsockfd);
    }

    // Stäng serverns socket när servern stängs
    close(sockfd);

    return 0;
}
