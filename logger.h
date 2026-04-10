#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
void logger_init(const char *);
int logger_open(char *);
void logger_write_hex(char *buffer,size_t size);
void logger_write_printable(char *buffer,size_t size);
void logger_write(char *buffer,size_t size);
void logger_close();