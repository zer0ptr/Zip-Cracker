#include "zip_cracker.h"
#include <signal.h>
#include <zip.h>

// 线程工作数据结构
typedef struct {
    thread_pool_t *pool;
    int thread_id;
    password_generator_t *generator;
} thread_work_data_t;

// 工作线程函数
static void* worker_thread(void *arg) {
    thread_work_data_t *data = (thread_work_data_t*)arg;
    thread_pool_t *pool = data->pool;
    attack_status_t *status = pool->status;
    
    archive_type_t archive_type = detect_archive_type(pool->target_file);
    
    char *password;
    while (!status->stop && (password = get_next_password(data->generator)) != NULL) {
        // 更新当前尝试的密码
        pthread_mutex_lock(&status->lock);
        if (status->current_password) {
            free(status->current_password);
        }
        status->current_password = strdup(password);
        pthread_mutex_unlock(&status->lock);
        
        // 尝试密码
        if (try_password(pool->target_file, password, archive_type)) {
            pthread_mutex_lock(&status->lock);
            if (!status->stop) {
                print_success("\n[*] 密码破解成功: %s", password);
                
                // 尝试解压文件
                char output_dir[256];
                snprintf(output_dir, sizeof(output_dir), "./extracted_%ld", time(NULL));
                
                if (extract_with_password(pool->target_file, password, output_dir, archive_type)) {
                    print_success("[*] 文件解压成功，输出目录: %s", output_dir);
                } else {
                    print_error("[!] 文件解压失败");
                }
                
                status->stop = true;
            }
            pthread_mutex_unlock(&status->lock);
            free(password);
            break;
        }
        
        // 更新尝试次数
        pthread_mutex_lock(&status->lock);
        status->tried_passwords++;
        pthread_mutex_unlock(&status->lock);
        
        free(password);
    }
    
    return NULL;
}

// CRC32攻击线程函数
static void* crc_attack_thread(void *arg) {
    thread_pool_t *pool = (thread_pool_t*)arg;
    attack_status_t *status = pool->status;
    
    // 分析压缩包，寻找小文件
    archive_info_t *info = analyze_archive(pool->target_file);
    if (!info) {
        print_error("无法分析压缩包进行CRC攻击");
        return NULL;
    }
    
    if (info->type != ARCHIVE_ZIP) {
        print_info("CRC攻击仅支持ZIP格式");
        free_archive_info(info);
        return NULL;
    }
    
    // 打开ZIP文件查找小文件
    int err;
    zip_t *archive = zip_open(pool->target_file, ZIP_RDONLY, &err);
    if (!archive) {
        free_archive_info(info);
        return NULL;
    }
    
    zip_uint64_t num_entries = zip_get_num_entries(archive, 0);
    bool found_small_file = false;
    
    for (zip_uint64_t i = 0; i < num_entries && !status->stop; i++) {
        zip_stat_t stat;
        if (zip_stat_index(archive, i, 0, &stat) == 0) {
            // 检查是否为小文件
            if (stat.size <= 8 && stat.size > 0) {
                print_info("发现小文件 %s (%lu 字节)，开始CRC32攻击", stat.name, (unsigned long)stat.size);
                found_small_file = true;
                
                char result[32];
                if (crc32_attack(stat.name, stat.crc, (int)stat.size, result)) {
                    print_success("CRC32攻击成功，文件内容: %s", result);
                    
                    // 这里可以根据文件内容推测密码
                    // 例如，如果内容是"flag{"，密码可能包含相关信息
                    
                    pthread_mutex_lock(&status->lock);
                    status->stop = true;
                    pthread_mutex_unlock(&status->lock);
                    break;
                }
            }
        }
    }
    
    if (!found_small_file) {
        print_info("未发现适合CRC攻击的小文件");
    }
    
    zip_close(archive);
    free_archive_info(info);
    return NULL;
}

// 创建线程池
thread_pool_t* create_thread_pool(int thread_count, const char *target_file, 
                                  const char *dict_file, attack_mode_t mode) {
    if (thread_count <= 0 || !target_file) {
        return NULL;
    }
    
    thread_pool_t *pool = calloc(1, sizeof(thread_pool_t));
    if (!pool) return NULL;
    
    pool->thread_count = thread_count;
    pool->target_file = strdup(target_file);
    pool->dict_file = dict_file ? strdup(dict_file) : NULL;
    pool->mode = mode;
    
    // 初始化攻击状态
    pool->status = calloc(1, sizeof(attack_status_t));
    if (!pool->status) {
        free(pool->target_file);
        free(pool->dict_file);
        free(pool);
        return NULL;
    }
    
    pool->status->stop = false;
    pool->status->tried_passwords = 0;
    pool->status->start_time = time(NULL);
    pool->status->current_password = NULL;
    
    if (pthread_mutex_init(&pool->status->lock, NULL) != 0) {
        free(pool->status);
        free(pool->target_file);
        free(pool->dict_file);
        free(pool);
        return NULL;
    }
    
    // 计算总密码数
    if (mode == ATTACK_DICTIONARY || mode == ATTACK_HYBRID) {
        if (dict_file) {
            pool->status->total_passwords = count_passwords_in_dict(dict_file);
        }
    }
    
    if (mode == ATTACK_BRUTEFORCE || mode == ATTACK_HYBRID) {
        // 添加数字密码数量（1-8位）
        for (int len = 1; len <= 8; len++) {
            uint64_t count = 1;
            for (int i = 0; i < len; i++) {
                count *= 10;
            }
            pool->status->total_passwords += count;
        }
    }
    
    // 分配线程数组
    pool->threads = calloc(thread_count, sizeof(pthread_t));
    if (!pool->threads) {
        pthread_mutex_destroy(&pool->status->lock);
        free(pool->status);
        free(pool->target_file);
        free(pool->dict_file);
        free(pool);
        return NULL;
    }
    
    return pool;
}

// 开始攻击
void start_attack(thread_pool_t *pool) {
    if (!pool) return;
    
    print_info("开始攻击，总密码数: %lu", pool->status->total_passwords);
    
    // 如果是CRC攻击或混合攻击，先尝试CRC攻击
    if (pool->mode == ATTACK_CRC32 || pool->mode == ATTACK_HYBRID) {
        pthread_t crc_thread;
        if (pthread_create(&crc_thread, NULL, crc_attack_thread, pool) == 0) {
            pthread_join(crc_thread, NULL);
            
            if (pool->status->stop) {
                return; // CRC攻击成功
            }
        }
    }
    
    // 如果只是CRC攻击模式且已经尝试过，直接返回
    if (pool->mode == ATTACK_CRC32) {
        return;
    }
    
    // 创建进度显示线程
    pthread_t progress_thread_id;
    pthread_create(&progress_thread_id, NULL, progress_thread, pool->status);
    
    // 创建工作线程数据
    thread_work_data_t *work_data = calloc(pool->thread_count, sizeof(thread_work_data_t));
    if (!work_data) {
        print_error("无法分配工作线程数据");
        return;
    }
    
    // 创建密码生成器
    for (int i = 0; i < pool->thread_count; i++) {
        work_data[i].pool = pool;
        work_data[i].thread_id = i;
        
        // 根据攻击模式创建不同的密码生成器
        if (pool->mode == ATTACK_DICTIONARY || 
            (pool->mode == ATTACK_HYBRID && i < pool->thread_count / 2)) {
            if (pool->dict_file) {
                work_data[i].generator = create_dict_generator(pool->dict_file);
            }
        } else {
            // 为不同线程分配不同长度的数字密码
            int min_len = (i % 8) + 1;
            int max_len = min_len;
            work_data[i].generator = create_numeric_generator(min_len, max_len);
        }
        
        if (!work_data[i].generator) {
            print_error("无法创建密码生成器 (线程 %d)", i);
            continue;
        }
    }
    
    // 启动工作线程
    for (int i = 0; i < pool->thread_count; i++) {
        if (work_data[i].generator) {
            if (pthread_create(&pool->threads[i], NULL, worker_thread, &work_data[i]) != 0) {
                print_error("无法创建工作线程 %d", i);
            }
        }
    }
    
    // 等待所有工作线程完成
    for (int i = 0; i < pool->thread_count; i++) {
        if (work_data[i].generator) {
            pthread_join(pool->threads[i], NULL);
        }
    }
    
    // 停止进度显示线程
    pool->status->stop = true;
    pthread_join(progress_thread_id, NULL);
    
    // 清理密码生成器
    for (int i = 0; i < pool->thread_count; i++) {
        if (work_data[i].generator) {
            free_password_generator(work_data[i].generator);
        }
    }
    free(work_data);
    
    if (!pool->status->stop) {
        print_error("\n[!] 攻击完成，未找到正确密码");
    }
}

// 停止攻击
void stop_attack(thread_pool_t *pool) {
    if (!pool || !pool->status) return;
    
    pthread_mutex_lock(&pool->status->lock);
    pool->status->stop = true;
    pthread_mutex_unlock(&pool->status->lock);
}

// 释放线程池
void free_thread_pool(thread_pool_t *pool) {
    if (!pool) return;
    
    if (pool->status) {
        pthread_mutex_destroy(&pool->status->lock);
        free(pool->status->current_password);
        free(pool->status);
    }
    
    free(pool->threads);
    free(pool->target_file);
    free(pool->dict_file);
    free(pool);
}