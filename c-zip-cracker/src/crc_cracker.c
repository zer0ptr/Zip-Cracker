#include "../include/zip_cracker.h"
#include <zlib.h>

// CRC32查找表（用于快速计算）
static uint32_t crc_table[256];
static bool crc_table_initialized = false;

// 初始化CRC32查找表
static void init_crc_table(void) {
    if (crc_table_initialized) return;
    
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc_table[i] = crc;
    }
    crc_table_initialized = true;
}

// 计算CRC32值
uint32_t calculate_crc32(const char *data, size_t len) {
    init_crc_table();
    
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

// 使用zlib计算CRC32（更快）
uint32_t calculate_crc32_zlib(const char *data, size_t len) {
    return crc32(0L, (const Bytef*)data, len);
}

// 生成指定长度的所有可能字符串并检查CRC32
static bool crc32_bruteforce_recursive(char *buffer, int pos, int max_len, 
                                      uint32_t target_crc, char *result) {
    // 可打印字符集
    static const char charset[] = 
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "!@#$%^&*()_+-=[]{}|;:,.<>?";
    static const int charset_len = sizeof(charset) - 1;
    
    if (pos == max_len) {
        buffer[pos] = '\0';
        uint32_t crc = calculate_crc32_zlib(buffer, max_len);
        if (crc == target_crc) {
            strcpy(result, buffer);
            return true;
        }
        return false;
    }
    
    for (int i = 0; i < charset_len; i++) {
        buffer[pos] = charset[i];
        if (crc32_bruteforce_recursive(buffer, pos + 1, max_len, target_crc, result)) {
            return true;
        }
    }
    
    return false;
}

// 优化的CRC32攻击（针对小文件）
bool crc32_attack(const char *filename, uint32_t target_crc, int file_size, char *result) {
    if (file_size <= 0 || file_size > 8) {
        print_error("CRC32攻击仅支持1-8字节的小文件");
        return false;
    }
    
    print_info("开始CRC32碰撞攻击，目标CRC: 0x%08X，文件大小: %d字节", target_crc, file_size);
    
    char buffer[16];
    
    // 对于1-4字节的文件，使用完全暴力破解
    if (file_size <= 4) {
        uint64_t total_combinations = 1;
        for (int i = 0; i < file_size; i++) {
            total_combinations *= 256;
        }
        
        print_info("尝试 %lu 种组合...", total_combinations);
        
        for (uint64_t combo = 0; combo < total_combinations; combo++) {
            uint64_t temp = combo;
            for (int i = 0; i < file_size; i++) {
                buffer[i] = temp & 0xFF;
                temp >>= 8;
            }
            
            uint32_t crc = calculate_crc32_zlib(buffer, file_size);
            if (crc == target_crc) {
                // 检查是否为可打印字符
                bool printable = true;
                for (int i = 0; i < file_size; i++) {
                    if (buffer[i] < 32 || buffer[i] > 126) {
                        printable = false;
                        break;
                    }
                }
                
                if (printable) {
                    buffer[file_size] = '\0';
                    strcpy(result, buffer);
                    print_success("找到CRC32碰撞: %s", result);
                    return true;
                }
            }
            
            // 每100万次显示进度
            if (combo % 1000000 == 0 && combo > 0) {
                printf("\r[*] 进度: %.2f%%", (double)combo / total_combinations * 100);
                fflush(stdout);
            }
        }
        printf("\n");
    } else {
        // 对于较大的文件，使用可打印字符集
        print_info("使用可打印字符集进行攻击...");
        if (crc32_bruteforce_recursive(buffer, 0, file_size, target_crc, result)) {
            print_success("找到CRC32碰撞: %s", result);
            return true;
        }
    }
    
    print_error("CRC32攻击失败，未找到匹配的内容");
    return false;
}

// 针对常见模式的CRC32攻击
bool crc32_attack_patterns(uint32_t target_crc, int file_size, char *result) {
    if (file_size <= 0 || file_size > 16) {
        return false;
    }
    
    // 常见的模式
    const char *patterns[] = {
        "flag{",
        "FLAG{",
        "ctf{",
        "CTF{",
        "key:",
        "pass:",
        "password:",
        "secret:",
        "admin",
        "root",
        "user",
        "test",
        "demo",
        "123456",
        "password",
        "qwerty",
        "abc123",
        "admin123",
        "root123",
        "test123"
    };
    
    int pattern_count = sizeof(patterns) / sizeof(patterns[0]);
    
    print_info("尝试常见模式...");
    
    for (int i = 0; i < pattern_count; i++) {
        const char *pattern = patterns[i];
        int pattern_len = strlen(pattern);
        
        if (pattern_len == file_size) {
            uint32_t crc = calculate_crc32_zlib(pattern, pattern_len);
            if (crc == target_crc) {
                strcpy(result, pattern);
                print_success("找到匹配模式: %s", result);
                return true;
            }
        } else if (pattern_len < file_size) {
            // 尝试在模式后添加数字
            char buffer[32];
            strcpy(buffer, pattern);
            
            int remaining = file_size - pattern_len;
            if (remaining <= 6) { // 最多6位数字
                for (int num = 0; num < (1 << (remaining * 4)); num++) {
                    snprintf(buffer + pattern_len, sizeof(buffer) - pattern_len, 
                            "%0*d", remaining, num);
                    
                    uint32_t crc = calculate_crc32_zlib(buffer, file_size);
                    if (crc == target_crc) {
                        strcpy(result, buffer);
                        print_success("找到匹配模式: %s", result);
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}

// 多线程CRC32攻击
typedef struct {
    uint32_t target_crc;
    int file_size;
    uint64_t start_range;
    uint64_t end_range;
    char *result;
    bool *found;
    pthread_mutex_t *mutex;
} crc_thread_data_t;

static void* crc_thread_worker(void *arg) {
    crc_thread_data_t *data = (crc_thread_data_t*)arg;
    char buffer[16];
    
    for (uint64_t combo = data->start_range; combo < data->end_range; combo++) {
        pthread_mutex_lock(data->mutex);
        if (*data->found) {
            pthread_mutex_unlock(data->mutex);
            break;
        }
        pthread_mutex_unlock(data->mutex);
        
        uint64_t temp = combo;
        for (int i = 0; i < data->file_size; i++) {
            buffer[i] = temp & 0xFF;
            temp >>= 8;
        }
        
        uint32_t crc = calculate_crc32_zlib(buffer, data->file_size);
        if (crc == data->target_crc) {
            // 检查是否为可打印字符
            bool printable = true;
            for (int i = 0; i < data->file_size; i++) {
                if (buffer[i] < 32 || buffer[i] > 126) {
                    printable = false;
                    break;
                }
            }
            
            if (printable) {
                pthread_mutex_lock(data->mutex);
                if (!*data->found) {
                    buffer[data->file_size] = '\0';
                    strcpy(data->result, buffer);
                    *data->found = true;
                }
                pthread_mutex_unlock(data->mutex);
                break;
            }
        }
    }
    
    return NULL;
}

// 多线程CRC32攻击
bool crc32_attack_threaded(uint32_t target_crc, int file_size, char *result, int thread_count) {
    if (file_size <= 0 || file_size > 4) {
        return false;
    }
    
    uint64_t total_combinations = 1;
    for (int i = 0; i < file_size; i++) {
        total_combinations *= 256;
    }
    
    if (thread_count <= 0) {
        thread_count = get_cpu_count();
    }
    
    print_info("使用%d个线程进行CRC32攻击", thread_count);
    
    pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
    crc_thread_data_t *thread_data = malloc(thread_count * sizeof(crc_thread_data_t));
    bool found = false;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    uint64_t range_size = total_combinations / thread_count;
    
    for (int i = 0; i < thread_count; i++) {
        thread_data[i].target_crc = target_crc;
        thread_data[i].file_size = file_size;
        thread_data[i].start_range = i * range_size;
        thread_data[i].end_range = (i == thread_count - 1) ? total_combinations : (i + 1) * range_size;
        thread_data[i].result = result;
        thread_data[i].found = &found;
        thread_data[i].mutex = &mutex;
        
        pthread_create(&threads[i], NULL, crc_thread_worker, &thread_data[i]);
    }
    
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    free(thread_data);
    pthread_mutex_destroy(&mutex);
    
    return found;
}