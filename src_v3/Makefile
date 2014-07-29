CC = gcc
OBJS = sad.o spd.o auth.o crypto.o window.o ipsec.o checksum.o setkey.o receiver.o  
SRCS = $(OBJS:%.o=%.c)
LIBS = -lcrypto 
CFLAGS = -O2 -Wall -I ./include -std=gnu99 -pthread #-D_GW2_#-D_TRANSPORT_ 
TARGET = ipsec 
 
.SUFFIXES : .c .o
 
all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

#depend : 
#	gccmakedep $(SRCS)
				 
clean :
	rm -f $(OBJS) $(TARGET)
	cp checksum checksum.o		 
