#include "../include/zip_cracker.h"
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <stdarg.h>
#include <errno.h>

// ANSI颜色代码
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

// 获取CPU核心数
int get_cpu_count(void) {
    return get_nprocs();
}

// 获取文件扩展名
char* get_file_extension(const char *filename) {
    if (!filename) return NULL;
    
    char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return NULL;
    
    return dot;
}

// 检查文件是否存在
bool file_exists(const char *filename) {
    if (!filename) return false;
    
    struct stat st;
    return stat(filename, &st) == 0;
}

// 获取文件大小
size_t get_file_size(const char *filename) {
    if (!filename) return 0;
    
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return 0;
}

// 打印错误信息
void print_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    printf(COLOR_RED "[!] ");
    vprintf(format, args);
    printf(COLOR_RESET "\n");
    
    va_end(args);
}

// 打印信息
void print_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    printf(COLOR_BLUE "[*] ");
    vprintf(format, args);
    printf(COLOR_RESET "\n");
    
    va_end(args);
}

// 打印成功信息
void print_success(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    printf(COLOR_GREEN "[+] ");
    vprintf(format, args);
    printf(COLOR_RESET "\n");
    
    va_end(args);
}

// 打印横幅
void print_banner(void) {
    printf(COLOR_CYAN COLOR_BOLD);
    printf("\n");
    printf(" ██████╗    ███████╗██╗██████╗      ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ \n");
    printf("██╔════╝    ╚══███╔╝██║██╔══██╗    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗\n");
    printf("██║           ███╔╝ ██║██████╔╝    ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝\n");
    printf("██║          ███╔╝  ██║██╔═══╝     ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗\n");
    printf("╚██████╗    ███████╗██║██║         ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║\n");
    printf(" ╚═════╝    ╚══════╝╚═╝╚═╝          ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n");
    printf(COLOR_RESET);
    printf("\n");
    printf(COLOR_YELLOW "                    高性能压缩包密码破解工具 - C语言版本\n" COLOR_RESET);
    printf(COLOR_MAGENTA "                    支持 ZIP/RAR/7Z 格式 | 多线程并行处理\n" COLOR_RESET);
    printf(COLOR_CYAN "                    原作者: Asaotomo@Hx0-Team | C版本重构\n" COLOR_RESET);
    printf("\n");
}

// 进度显示线程
void* progress_thread(void *arg) {
    attack_status_t *status = (attack_status_t*)arg;
    
    while (!status->stop) {
        usleep(100000); // 100ms
        print_progress(status);
    }
    
    // 最后一次显示进度
    print_progress(status);
    printf("\n");
    
    return NULL;
}

// 打印进度信息
void print_progress(attack_status_t *status) {
    pthread_mutex_lock(&status->lock);
    
    uint64_t tried = status->tried_passwords;
    uint64_t total = status->total_passwords;
    time_t current_time = time(NULL);
    time_t elapsed = current_time - status->start_time;
    
    double progress = 0.0;
    if (total > 0) {
        progress = (double)tried / total * 100.0;
    }
    
    uint64_t speed = 0;
    if (elapsed > 0) {
        speed = tried / elapsed;
    }
    
    time_t remaining = 0;
    if (speed > 0 && total > tried) {
        remaining = (total - tried) / speed;
    }
    
    char current_password[32] = "N/A";
    if (status->current_password) {
        strncpy(current_password, status->current_password, sizeof(current_password) - 1);
        current_password[sizeof(current_password) - 1] = '\0';
    }
    
    // 格式化剩余时间
    char time_str[32];
    if (remaining > 0) {
        int hours = remaining / 3600;
        int minutes = (remaining % 3600) / 60;
        int seconds = remaining % 60;
        snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d", hours, minutes, seconds);
    } else {
        strcpy(time_str, "N/A");
    }
    
    pthread_mutex_unlock(&status->lock);
    
    // 打印进度条
    printf("\r" COLOR_YELLOW "[进度] " COLOR_RESET);
    printf("%.2f%% | ", progress);
    printf(COLOR_CYAN "剩余时间: %s" COLOR_RESET " | ", time_str);
    printf(COLOR_GREEN "速度: %lu p/s" COLOR_RESET " | ", speed);
    printf(COLOR_MAGENTA "当前: %-20s" COLOR_RESET, current_password);
    fflush(stdout);
}

// 格式化字节大小
char* format_bytes(uint64_t bytes) {
    static char buffer[32];
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = bytes;
    
    while (size >= 1024 && unit_index < 4) {
        size /= 1024;
        unit_index++;
    }
    
    if (unit_index == 0) {
        snprintf(buffer, sizeof(buffer), "%lu %s", bytes, units[unit_index]);
    } else {
        snprintf(buffer, sizeof(buffer), "%.2f %s", size, units[unit_index]);
    }
    
    return buffer;
}

// 格式化时间
char* format_time(time_t seconds) {
    static char buffer[32];
    
    if (seconds < 60) {
        snprintf(buffer, sizeof(buffer), "%ld秒", seconds);
    } else if (seconds < 3600) {
        snprintf(buffer, sizeof(buffer), "%ld分%ld秒", seconds / 60, seconds % 60);
    } else if (seconds < 86400) {
        snprintf(buffer, sizeof(buffer), "%ld小时%ld分", seconds / 3600, (seconds % 3600) / 60);
    } else {
        snprintf(buffer, sizeof(buffer), "%ld天%ld小时", seconds / 86400, (seconds % 86400) / 3600);
    }
    
    return buffer;
}

// 创建目录（递归）
bool create_directory(const char *path) {
    if (!path) return false;
    
    char *path_copy = strdup(path);
    if (!path_copy) return false;
    
    char *p = path_copy;
    
    // 跳过根目录
    if (*p == '/') p++;
    
    while (*p) {
        while (*p && *p != '/') p++;
        
        char temp = *p;
        *p = '\0';
        
        if (mkdir(path_copy, 0755) != 0 && errno != EEXIST) {
            free(path_copy);
            return false;
        }
        
        *p = temp;
        if (*p) p++;
    }
    
    free(path_copy);
    return true;
}

// 获取系统信息
void print_system_info(void) {
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        print_info("系统信息:");
        printf("  CPU核心数: %d\n", get_cpu_count());
        printf("  总内存: %s\n", format_bytes(si.totalram * si.mem_unit));
        printf("  可用内存: %s\n", format_bytes(si.freeram * si.mem_unit));
        printf("  系统运行时间: %s\n", format_time(si.uptime));
    }
}

// 检查系统资源
bool check_system_resources(void) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        return true; // 无法获取信息，假设资源充足
    }
    
    // 检查可用内存（至少需要100MB）
    uint64_t available_memory = si.freeram * si.mem_unit;
    if (available_memory < 100 * 1024 * 1024) {
        print_error("可用内存不足，建议至少100MB可用内存");
        return false;
    }
    
    return true;
}

// 安全的字符串复制
char* safe_strdup(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    char *copy = malloc(len + 1);
    if (copy) {
        memcpy(copy, str, len + 1);
    }
    return copy;
}

// 安全的字符串连接
char* safe_strcat(const char *str1, const char *str2) {
    if (!str1 && !str2) return NULL;
    if (!str1) return safe_strdup(str2);
    if (!str2) return safe_strdup(str1);
    
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    char *result = malloc(len1 + len2 + 1);
    
    if (result) {
        memcpy(result, str1, len1);
        memcpy(result + len1, str2, len2 + 1);
    }
    
    return result;
}