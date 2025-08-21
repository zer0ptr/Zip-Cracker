#include "zip_cracker.h"
#include <zip.h>
#include <archive.h>
#include <archive_entry.h>
#include <unistd.h>
#include <errno.h>

// 尝试使用密码解压ZIP文件
static bool try_zip_password(const char *archive_path, const char *password) {
    int err;
    zip_t *archive = zip_open(archive_path, ZIP_RDONLY, &err);
    if (!archive) {
        return false;
    }
    
    // 设置密码
    if (zip_set_default_password(archive, password) != 0) {
        zip_close(archive);
        return false;
    }
    
    // 尝试读取第一个加密文件
    zip_uint64_t num_entries = zip_get_num_entries(archive, 0);
    bool success = false;
    
    for (zip_uint64_t i = 0; i < num_entries && !success; i++) {
        zip_stat_t stat;
        if (zip_stat_index(archive, i, 0, &stat) == 0) {
            if (stat.encryption_method != ZIP_EM_NONE) {
                zip_file_t *file = zip_fopen_index(archive, i, 0);
                if (file) {
                    // 尝试读取一些数据来验证密码
                    char buffer[1024];
                    zip_int64_t bytes_read = zip_fread(file, buffer, sizeof(buffer));
                    if (bytes_read >= 0) {
                        success = true;
                    }
                    zip_fclose(file);
                }
            }
        }
    }
    
    zip_close(archive);
    return success;
}

// 尝试使用密码解压RAR文件
static bool try_rar_password(const char *archive_path, const char *password) {
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_rar(a);
    archive_read_add_passphrase(a, password);
    
    if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK) {
        archive_read_free(a);
        return false;
    }
    
    struct archive_entry *entry;
    bool success = false;
    
    // 尝试读取第一个加密条目
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        if (archive_entry_is_encrypted(entry)) {
            // 尝试读取一些数据
            char buffer[1024];
            la_ssize_t bytes_read = archive_read_data(a, buffer, sizeof(buffer));
            if (bytes_read >= 0) {
                success = true;
                break;
            }
        } else {
            archive_read_data_skip(a);
        }
    }
    
    archive_read_free(a);
    return success;
}

// 尝试使用密码解压7Z文件
static bool try_7z_password(const char *archive_path, const char *password) {
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_7zip(a);
    archive_read_add_passphrase(a, password);
    
    if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK) {
        archive_read_free(a);
        return false;
    }
    
    struct archive_entry *entry;
    bool success = false;
    
    // 尝试读取第一个加密条目
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        if (archive_entry_is_encrypted(entry)) {
            // 尝试读取一些数据
            char buffer[1024];
            la_ssize_t bytes_read = archive_read_data(a, buffer, sizeof(buffer));
            if (bytes_read >= 0) {
                success = true;
                break;
            }
        } else {
            archive_read_data_skip(a);
        }
    }
    
    archive_read_free(a);
    return success;
}

// 尝试密码
bool try_password(const char *archive_path, const char *password, archive_type_t type) {
    if (!archive_path || !password) {
        return false;
    }
    
    switch (type) {
        case ARCHIVE_ZIP:
            return try_zip_password(archive_path, password);
        case ARCHIVE_RAR:
            return try_rar_password(archive_path, password);
        case ARCHIVE_7Z:
            return try_7z_password(archive_path, password);
        default:
            return false;
    }
}

// 使用密码解压ZIP文件
static bool extract_zip_with_password(const char *archive_path, const char *password, 
                                     const char *output_dir) {
    int err;
    zip_t *archive = zip_open(archive_path, ZIP_RDONLY, &err);
    if (!archive) {
        return false;
    }
    
    if (zip_set_default_password(archive, password) != 0) {
        zip_close(archive);
        return false;
    }
    
    // 创建输出目录
    if (access(output_dir, F_OK) != 0) {
        if (mkdir(output_dir, 0755) != 0) {
            zip_close(archive);
            return false;
        }
    }
    
    zip_uint64_t num_entries = zip_get_num_entries(archive, 0);
    bool success = true;
    
    for (zip_uint64_t i = 0; i < num_entries && success; i++) {
        zip_stat_t stat;
        if (zip_stat_index(archive, i, 0, &stat) == 0) {
            // 构建输出文件路径
            char output_path[1024];
            snprintf(output_path, sizeof(output_path), "%s/%s", output_dir, stat.name);
            
            // 如果是目录，创建目录
            if (stat.name[strlen(stat.name) - 1] == '/') {
                if (mkdir(output_path, 0755) != 0 && errno != EEXIST) {
                    success = false;
                    break;
                }
                continue;
            }
            
            // 打开ZIP文件中的条目
            zip_file_t *file = zip_fopen_index(archive, i, 0);
            if (!file) {
                success = false;
                break;
            }
            
            // 创建输出文件
            FILE *output_file = fopen(output_path, "wb");
            if (!output_file) {
                zip_fclose(file);
                success = false;
                break;
            }
            
            // 复制数据
            char buffer[8192];
            zip_int64_t bytes_read;
            while ((bytes_read = zip_fread(file, buffer, sizeof(buffer))) > 0) {
                if (fwrite(buffer, 1, (size_t)bytes_read, output_file) != (size_t)bytes_read) {
                    success = false;
                    break;
                }
            }
            
            fclose(output_file);
            zip_fclose(file);
            
            if (bytes_read < 0) {
                success = false;
            }
        }
    }
    
    zip_close(archive);
    return success;
}

// 使用密码解压RAR文件
static bool extract_rar_with_password(const char *archive_path, const char *password, 
                                     const char *output_dir) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    
    archive_read_support_filter_all(a);
    archive_read_support_format_rar(a);
    archive_read_add_passphrase(a, password);
    
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM);
    
    if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK) {
        archive_read_free(a);
        archive_write_free(ext);
        return false;
    }
    
    // 创建输出目录
    if (access(output_dir, F_OK) != 0) {
        if (mkdir(output_dir, 0755) != 0) {
            archive_read_free(a);
            archive_write_free(ext);
            return false;
        }
    }
    
    struct archive_entry *entry;
    bool success = true;
    
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK && success) {
        // 修改路径前缀
        const char *current_file = archive_entry_pathname(entry);
        char new_path[1024];
        snprintf(new_path, sizeof(new_path), "%s/%s", output_dir, current_file);
        archive_entry_set_pathname(entry, new_path);
        
        if (archive_write_header(ext, entry) != ARCHIVE_OK) {
            success = false;
            break;
        }
        
        if (archive_entry_size(entry) > 0) {
            const void *buff;
            size_t size;
            la_int64_t offset;
            
            while (archive_read_data_block(a, &buff, &size, &offset) == ARCHIVE_OK) {
                if (archive_write_data_block(ext, buff, size, offset) != ARCHIVE_OK) {
                    success = false;
                    break;
                }
            }
        }
        
        if (archive_write_finish_entry(ext) != ARCHIVE_OK) {
            success = false;
        }
    }
    
    archive_read_free(a);
    archive_write_free(ext);
    return success;
}

// 使用密码解压7Z文件
static bool extract_7z_with_password(const char *archive_path, const char *password, 
                                    const char *output_dir) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    
    archive_read_support_filter_all(a);
    archive_read_support_format_7zip(a);
    archive_read_add_passphrase(a, password);
    
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM);
    
    if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK) {
        archive_read_free(a);
        archive_write_free(ext);
        return false;
    }
    
    // 创建输出目录
    if (access(output_dir, F_OK) != 0) {
        if (mkdir(output_dir, 0755) != 0) {
            archive_read_free(a);
            archive_write_free(ext);
            return false;
        }
    }
    
    struct archive_entry *entry;
    bool success = true;
    
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK && success) {
        // 修改路径前缀
        const char *current_file = archive_entry_pathname(entry);
        char new_path[1024];
        snprintf(new_path, sizeof(new_path), "%s/%s", output_dir, current_file);
        archive_entry_set_pathname(entry, new_path);
        
        if (archive_write_header(ext, entry) != ARCHIVE_OK) {
            success = false;
            break;
        }
        
        if (archive_entry_size(entry) > 0) {
            const void *buff;
            size_t size;
            la_int64_t offset;
            
            while (archive_read_data_block(a, &buff, &size, &offset) == ARCHIVE_OK) {
                if (archive_write_data_block(ext, buff, size, offset) != ARCHIVE_OK) {
                    success = false;
                    break;
                }
            }
        }
        
        if (archive_write_finish_entry(ext) != ARCHIVE_OK) {
            success = false;
        }
    }
    
    archive_read_free(a);
    archive_write_free(ext);
    return success;
}

// 使用密码解压文件
bool extract_with_password(const char *archive_path, const char *password, 
                          const char *output_dir, archive_type_t type) {
    if (!archive_path || !password || !output_dir) {
        return false;
    }
    
    switch (type) {
        case ARCHIVE_ZIP:
            return extract_zip_with_password(archive_path, password, output_dir);
        case ARCHIVE_RAR:
            return extract_rar_with_password(archive_path, password, output_dir);
        case ARCHIVE_7Z:
            return extract_7z_with_password(archive_path, password, output_dir);
        default:
            return false;
    }
}