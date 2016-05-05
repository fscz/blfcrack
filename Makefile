SOURCES := $(wildcard *.c)
OBJS := $(SOURCES:.c=.o)

CC := gcc
CFLAGS :=
LDFLAGS :=

%.o: %.c
	$(CC) -c $(CFLAGS) $< 

blfcrack: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@ 

clean:
	rm -f $(OBJS) blfcrack