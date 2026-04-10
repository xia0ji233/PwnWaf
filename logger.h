#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
void logger_init(const char *);
int logger_open(const char *);
void logger_write_hex(const char *buffer,size_t size);
void logger_write_printable(const char *buffer,size_t size);
void logger_write(const char *buffer,size_t size);
void logger_close();