CC := gcc
CFLAGS := -Wall -Wextra -std=c11 -Isrc

SRC := src/pbkdf2.c src/hmac/hmac.c src/hmac/sha256/sha256.c tests/test_pbkdf2.c
TARGET := test_pbkdf2

.PHONY: all build run clean

all: $(TARGET)

build: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)