#fisier folosit pentru compilarea serverului&clientului
#este necesar instalarea bibliotecilor ncurses, sqlite3 (apt install libncurses-dev libsqlite3-dev)

all:
	g++ -c common.cpp -o common.o
	g++ server.cpp common.o -std=c++14 -lsqlite3 -pthread -o server
	g++ client.cpp common.o -std=c++14 -lncurses -o client
	rm common.o
clean:
	rm client server
