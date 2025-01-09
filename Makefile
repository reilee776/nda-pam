CC = gcc

# Library and include paths
LIB_DIR = ./lib
CFLAGS = -fPIC -I$(LIB_DIR)/include -Wall -Wextra -g -std=c99
LDFLAGS = -shared -fPIC -L$(LIB_DIR) -Wl,-rpath,'$$ORIGIN/../lib'

# Libraries to link against
LIBS = -lcurl -lcrypto -lssl -ljson-c -lpam -lcrypt -luuid

# Target output
TARGET = nda-pam.so

# Source and object files
PAM_MODULE_SRC = nd_nix_pam.c
ND_UTILS_C = ./libsrc/nd_utils.c
ND_UTILS_H = ./libsrc/nd_utils.h
ND_LOGS_C = ./libsrc/nd_nix_logs.c
ND_LOGS_H = ./libsrc/nd_nix_logs.h
ND_RESTAPI_C = ./libsrc/nd_restapi_func.c
ND_RESTAPI_H = ./libsrc/nd_restapi_func.h

SRCS = $(PAM_MODULE_SRC) $(ND_UTILS_C) $(ND_LOGS_C) $(ND_RESTAPI_C)
HEADERS = $(ND_UTILS_H) $(ND_LOGS_H) $(ND_RESTAPI_H)
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build shared object
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

# Compile source files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
