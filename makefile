CC = gcc
CFLAGS = -Wall -Wextra -std=c99

kry: kry.c
	$(CC) $(CFLAGS) -o kry kry.c

clean:
	rm -f kry