CC = gcc
CFLAGS = -Wall -g -Iinclude
LDFLAGS = -lcurl -lssh -lm

# Build both executables
TARGETS = clickup_tasks clicky

SRC_DIR = src
OBJ_DIR = obj

# clickup_tasks (original)
CLICKUP_SRC = $(SRC_DIR)/main.c $(SRC_DIR)/mjson.c
CLICKUP_OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(CLICKUP_SRC))

# clicky (bash script parity)
CLICKY_SRC = $(SRC_DIR)/clicky.c $(SRC_DIR)/mjson.c
CLICKY_OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%-clicky.o, $(CLICKY_SRC))

.PHONY: all clean

all: $(TARGETS)

clickup_tasks: $(OBJ_DIR)/main.o $(OBJ_DIR)/mjson.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clicky: $(OBJ_DIR)/clicky.o $(OBJ_DIR)/mjson-clicky.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%-clicky.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJ_DIR) $(TARGETS)
