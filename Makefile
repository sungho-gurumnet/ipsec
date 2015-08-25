.PHONY: run all depend clean
#-nostdinc 
CFLAGS = -I ../../include -O2 -Wall -g -m64 -ffreestanding -std=gnu99 -Werror -fno-stack-protector
DIR = obj 

OBJS = obj/sad.o obj/sa.o obj/spd.o obj/sp.o obj/crypto.o obj/auth.o obj/main.o \
       obj/window.o obj/ipsec.o obj/content.o obj/socket.o obj/ike.o obj/mode.o

LIBS = --start-group ../../lib/libpacketngin.a ../../lib/libcrypto.a ../../lib/libssl.a --end-group

all: $(OBJS)
	ld -melf_x86_64 -nostdlib -e main -o main $^ $(LIBS) 

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj
	rm -f main

run: all 
	../../bin/console script
