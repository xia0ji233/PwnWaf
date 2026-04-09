#include "logger.h"

char logger_path[0x100];
int logger_fd=-1;
const char HEX[]="Hex = \"";
const char RAW[]="Raw = \"";
int logger_open(char *file){
    logger_fd = open(file, O_CREAT | O_APPEND | O_WRONLY, 0666);
    if(logger_fd == -1) {
        perror("open:");
        return 0;
    }
    return 1;
}

void logger_init(const char *path) {
	if (access(path, R_OK | W_OK) != 0) {
		mkdir(path, 0777);
	}
    strncpy(logger_path, path, sizeof(logger_path) - 1);
    logger_path[sizeof(logger_path) - 1] = '\0';
}

void logger_write_hex(char *buffer,size_t size){
    char byte[0x10];
    write(logger_fd,"\"",1);
    for(int i=0;i<size;i++){
        sprintf(byte,"\\x%02x",(unsigned char)buffer[i]);
        write(logger_fd,byte,4);//通常是一个字节用四个字节打印
    }
    write(logger_fd,"\"\n",2);
}

void logger_write_printable(char *buffer,size_t size){//构造可打印字符，不可打印字符用.代替
    write(logger_fd,RAW,sizeof(RAW)-1);
    for(int i=0;i<size;i++){
        if(buffer[i]>=0x20 && buffer[i]<0x7f){
            if(buffer[i]=='"'||buffer[i]=='\\'){
                write(logger_fd,"\\",1);
            }
            write(logger_fd,buffer+i,1);
        }
        else{ 
            write(logger_fd,".",1);
        }
    }
    write(logger_fd,"\"\n",2);
}

void logger_write(char *buffer,size_t size){
    write(logger_fd,buffer,size);
}
void logger_close(){
    close(logger_fd);
}