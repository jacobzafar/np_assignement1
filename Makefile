CC = g++
CFLAGS = -Wall -Wextra -std=c++11
TARGETS = server client

all: $(TARGETS)

server: servermain.cpp
	$(CC) $(CFLAGS) -o server servermain.cpp

client: clientmain.cpp
	$(CC) $(CFLAGS) -o client clientmain.cpp

clean:
	rm -f $(TARGETS)

.PHONY: all clean
