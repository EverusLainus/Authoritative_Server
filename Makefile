object =  main.o server.o
headers = main.h
main: main.o server.o
	clang -o main main.o server.o