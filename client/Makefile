CC = gcc
OBJS = client.o sender.o setkey.o 
SRCS = $(OBJS:%.o=%.c)
#LIBS = -lcrypto 
CFLAGS = -O2 -Wall -I ../../../../include -std=gnu99 -D_GW2_
TARGET = client
 
.SUFFIXES : .c .o
 
all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean :
	rm -f $(OBJS) $(TARGET)
