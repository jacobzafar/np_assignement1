#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>   // För att använda std::string
#include <sstream>  // För att använda std::stringstream
#include "calcLib.h" // Inkludera headern för din beräkningslogik

#define DEBUG

using namespace std;

void print_error(const char *message) {
    fprintf(stderr, "ERROR: %s\n", message);
}

int main(int argc, char *argv[]) {
    // Kontrollera att användaren skickat rätt argument (hostname:port)
    if (argc != 2) {
        print_error("Usage: ./server <hostname>:<port>");
        return 1;
    }

    char delim[] = ":";  // Delimitern för att dela upp host och port
    char *Desthost = strtok(argv[1], delim);  // Dela upp i host
    char *Destport = strtok(NULL, delim);    // Dela upp i port

    int port = atoi(Destport);  // Konvertera port från sträng till int

    // Debugutskrift: Skriv ut host och port
    #ifdef DEBUG
    printf("Host: %s, and Port: %d\n", Desthost, port);
    #endif

    // Skapa serverns socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("ERROR: Cannot open socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));  // Nollställ serverns adressstruktur
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Lyssna på alla nätverksinterface
    server_addr.sin_port = htons(port);  // Sätt porten till den angivna porten

    // Binda serverns socket till den angivna adressen
    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        print_error("ERROR: Cannot bind to socket");
        return 1;
    }

    listen(sockfd, 5);  // Vänta på inkommande anslutningar
    printf("Server is listening on port %d...\n", port);

    // Evig loop som accepterar anslutningar från klienter
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &client_len);
        if (newsockfd < 0) {
            print_error("ERROR: Failed to accept connection");
            continue;
        }

        // Läs operationen som skickas av klienten
        char buffer[256];
        bzero(buffer, 256);
        int n = read(newsockfd, buffer, 255);  // Läs från klienten
        if (n < 0) {
            print_error("ERROR: Failed to read from client");
            continue;
        }

        // Bearbeta operationen
        std::string operation(buffer);  // Skapa en sträng från det mottagna
        std::string result_str = "OK (myresult=<result>)\n";  // Resultat i rätt format

        // Här ska du implementera din beräkning. Exempel för add:
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
        }

        // Skicka tillbaka resultatet till klienten
        std::stringstream result_stream;
        result_stream << result;
        result_str.replace(result_str.find("<result>"), 8, result_stream.str());  // Ersätt <result> med det faktiska resultatet

        n = write(newsockfd, result_str.c_str(), result_str.length());  // Skicka tillbaka resultatet till klienten
        if (n < 0) {
            print_error("ERROR: Failed to send result to client");
            continue;
        }

        close(newsockfd);  // Stäng klientanslutningen när den är klar
    }

    close(sockfd);  // Stäng serverns socket när servern stängs
    return 0;
}