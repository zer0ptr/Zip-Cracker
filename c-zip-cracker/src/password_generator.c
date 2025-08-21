#include "../include/zip_cracker.h"

// 密码生成器结构
struct password_generator {
    enum {
        GEN_DICT,
        GEN_NUMERIC,
        GEN_ALPHA,
        GEN_ALPHANUM
    } type;
    
    union {
        struct {
            FILE *file;
            char *buffer;
            size_t buffer_size;
            bool eof_reached;
        } dict;
        
        struct {
            int current_length;
            int max_length;
            int min_length;
            char *current_password;
            bool finished;
        } numeric;
    } data;
};

// 创建字典密码生成器
password_generator_t* create_dict_generator(const char *dict_file) {
    if (!dict_file || !file_exists(dict_file)) {
        return NULL;
    }
    
    password_generator_t *gen = calloc(1, sizeof(password_generator_t));
    if (!gen) return NULL;
    
    gen->type = GEN_DICT;
    gen->data.dict.file = fopen(dict_file, "r");
    if (!gen->data.dict.file) {
        free(gen);
        return NULL;
    }
    
    gen->data.dict.buffer_size = 1024;
    gen->data.dict.buffer = malloc(gen->data.dict.buffer_size);
    if (!gen->data.dict.buffer) {
        fclose(gen->data.dict.file);
        free(gen);
        return NULL;
    }
    
    gen->data.dict.eof_reached = false;
    
    return gen;
}

// 创建数字密码生成器
password_generator_t* create_numeric_generator(int min_len, int max_len) {
    if (min_len <= 0 || max_len <= 0 || min_len > max_len || max_len > 20) {
        return NULL;
    }
    
    password_generator_t *gen = calloc(1, sizeof(password_generator_t));
    if (!gen) return NULL;
    
    gen->type = GEN_NUMERIC;
    gen->data.numeric.min_length = min_len;
    gen->data.numeric.max_length = max_len;
    gen->data.numeric.current_length = min_len;
    gen->data.numeric.finished = false;
    
    gen->data.numeric.current_password = calloc(max_len + 1, sizeof(char));
    if (!gen->data.numeric.current_password) {
        free(gen);
        return NULL;
    }
    
    // 初始化为第一个密码 (全0)
    for (int i = 0; i < min_len; i++) {
        gen->data.numeric.current_password[i] = '0';
    }
    gen->data.numeric.current_password[min_len] = '\0';
    
    return gen;
}

// 获取下一个字典密码
static char* get_next_dict_password(password_generator_t *gen) {
    if (gen->data.dict.eof_reached) {
        return NULL;
    }
    
    if (fgets(gen->data.dict.buffer, gen->data.dict.buffer_size, gen->data.dict.file)) {
        // 移除换行符
        size_t len = strlen(gen->data.dict.buffer);
        if (len > 0 && gen->data.dict.buffer[len-1] == '\n') {
            gen->data.dict.buffer[len-1] = '\0';
        }
        if (len > 1 && gen->data.dict.buffer[len-2] == '\r') {
            gen->data.dict.buffer[len-2] = '\0';
        }
        
        return strdup(gen->data.dict.buffer);
    } else {
        gen->data.dict.eof_reached = true;
        return NULL;
    }
}

// 递增数字密码
static bool increment_numeric_password(char *password, int length) {
    for (int i = length - 1; i >= 0; i--) {
        if (password[i] < '9') {
            password[i]++;
            return true;
        } else {
            password[i] = '0';
        }
    }
    return false; // 溢出
}

// 获取下一个数字密码
static char* get_next_numeric_password(password_generator_t *gen) {
    if (gen->data.numeric.finished) {
        return NULL;
    }
    
    char *result = strdup(gen->data.numeric.current_password);
    
    // 生成下一个密码
    if (!increment_numeric_password(gen->data.numeric.current_password, 
                                   gen->data.numeric.current_length)) {
        // 当前长度已经用完，增加长度
        gen->data.numeric.current_length++;
        
        if (gen->data.numeric.current_length > gen->data.numeric.max_length) {
            gen->data.numeric.finished = true;
        } else {
            // 重置为新长度的第一个密码
            for (int i = 0; i < gen->data.numeric.current_length; i++) {
                gen->data.numeric.current_password[i] = '0';
            }
            gen->data.numeric.current_password[gen->data.numeric.current_length] = '\0';
        }
    }
    
    return result;
}

// 获取下一个密码
char* get_next_password(password_generator_t *gen) {
    if (!gen) return NULL;
    
    switch (gen->type) {
        case GEN_DICT:
            return get_next_dict_password(gen);
        case GEN_NUMERIC:
            return get_next_numeric_password(gen);
        default:
            return NULL;
    }
}

// 释放密码生成器
void free_password_generator(password_generator_t *gen) {
    if (!gen) return;
    
    switch (gen->type) {
        case GEN_DICT:
            if (gen->data.dict.file) {
                fclose(gen->data.dict.file);
            }
            free(gen->data.dict.buffer);
            break;
        case GEN_NUMERIC:
            free(gen->data.numeric.current_password);
            break;
    }
    
    free(gen);
}

// 计算字典中的密码数量
uint64_t count_passwords_in_dict(const char *dict_file) {
    if (!dict_file || !file_exists(dict_file)) {
        return 0;
    }
    
    FILE *file = fopen(dict_file, "r");
    if (!file) return 0;
    
    uint64_t count = 0;
    char buffer[1024];
    
    while (fgets(buffer, sizeof(buffer), file)) {
        count++;
    }
    
    fclose(file);
    return count;
}

// 计算数字密码的总数量
uint64_t count_numeric_passwords(int min_len, int max_len) {
    uint64_t total = 0;
    for (int len = min_len; len <= max_len; len++) {
        uint64_t count = 1;
        for (int i = 0; i < len; i++) {
            count *= 10;
        }
        total += count;
    }
    return total;
}

// 创建字母密码生成器
password_generator_t* create_alpha_generator(int min_len, int max_len, bool include_uppercase) {
    // TODO: 实现字母密码生成器
    return NULL;
}

// 创建字母数字密码生成器
password_generator_t* create_alphanum_generator(int min_len, int max_len) {
    // TODO: 实现字母数字密码生成器
    return NULL;
}