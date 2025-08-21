#ifndef ZIP_CRACKER_H
#define ZIP_CRACKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

// 支持的压缩包格式
typedef enum {
    ARCHIVE_ZIP,
    ARCHIVE_RAR,
    ARCHIVE_7Z,
    ARCHIVE_UNKNOWN
} archive_type_t;

// 攻击模式
typedef enum {
    ATTACK_DICTIONARY,
    ATTACK_BRUTEFORCE,
    ATTACK_CRC32,
    ATTACK_HYBRID
} attack_mode_t;

// 压缩包信息结构
typedef struct {
    char *filename;
    archive_type_t type;
    bool is_encrypted;
    bool has_fake_encryption;
    uint32_t file_count;
    uint64_t total_size;
} archive_info_t;

// 文件条目信息
typedef struct {
    char *filename;
    uint32_t crc32;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    bool is_encrypted;
} file_entry_t;

// 攻击状态
typedef struct {
    bool stop;
    uint64_t tried_passwords;
    uint64_t total_passwords;
    time_t start_time;
    char *current_password;
    pthread_mutex_t lock;
} attack_status_t;

// 线程池配置
typedef struct {
    int thread_count;
    pthread_t *threads;
    attack_status_t *status;
    char *target_file;
    char *dict_file;
    attack_mode_t mode;
} thread_pool_t;

// 函数声明

// 压缩包分析
archive_type_t detect_archive_type(const char *filename);
archive_info_t* analyze_archive(const char *filename);
bool is_archive_encrypted(const char *filename, archive_type_t type);
bool has_fake_encryption(const char *filename);
bool fix_fake_encryption(const char *filename, const char *output_filename);
void free_archive_info(archive_info_t *info);

// 密码生成和字典
typedef struct password_generator password_generator_t;
password_generator_t* create_dict_generator(const char *dict_file);
password_generator_t* create_numeric_generator(int min_len, int max_len);
char* get_next_password(password_generator_t *gen);
void free_password_generator(password_generator_t *gen);
uint64_t count_passwords_in_dict(const char *dict_file);

// CRC32攻击
bool crc32_attack(const char *filename, uint32_t target_crc, int file_size, char *result);
uint32_t calculate_crc32(const char *data, size_t len);

// 暴力破解
bool try_password(const char *archive_path, const char *password, archive_type_t type);
bool extract_with_password(const char *archive_path, const char *password, 
                          const char *output_dir, archive_type_t type);

// 多线程攻击
thread_pool_t* create_thread_pool(int thread_count, const char *target_file, 
                                  const char *dict_file, attack_mode_t mode);
void start_attack(thread_pool_t *pool);
void stop_attack(thread_pool_t *pool);
void free_thread_pool(thread_pool_t *pool);

// 进度显示
void* progress_thread(void *arg);
void print_progress(attack_status_t *status);
void print_banner(void);

// 工具函数
int get_cpu_count(void);
char* get_file_extension(const char *filename);
bool file_exists(const char *filename);
size_t get_file_size(const char *filename);
void print_error(const char *format, ...);
void print_info(const char *format, ...);
void print_success(const char *format, ...);

#endif // ZIP_CRACKER_H