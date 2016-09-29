# the compiler
CC = gcc

# compiler flags:
#   -lpcap       uses pcap library
#   -Wall        turns on most compiler warnings
#   -Wextra      adds extra warnings
#   -std=c99     compile to the c99 standard
#   -g           adds debugging information to the executable file

CFLAGS = -lpcap -Wall -Wextra -std=c99 -g

# the build target executable
TARGET = project_1

all: $(TARGET) 

$(TARGET): $(TARGET).c
	$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET) 
