CC = gcc
DIR = obj
OBJS = obj/client.o obj/sender.o obj/setkey.o 
CFLAGS = -O0 -Wall -I ../../../include -std=gnu99
 
obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

all : $(OBJS)
	gcc -e main -o main $^

clean :
	rm -f main
	rm -rf $(DIR)
