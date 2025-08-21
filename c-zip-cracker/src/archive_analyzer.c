#include "../include/zip_cracker.h"
#include <zip.h>
#include <archive.h>
#include <archive_entry.h>
#include <sys/stat.h>

// 检测压缩包类型
archive_type_t detect_archive_type(const char *filename) {
    if (!filename) return ARCHIVE_UNKNOWN;
    
    char *ext = get_file_extension(filename);
    if (!ext) return ARCHIVE_UNKNOWN;
    
    if (strcasecmp(ext, ".zip") == 0) {
        return ARCHIVE_ZIP;
    } else if (strcasecmp(ext, ".rar") == 0) {
        return ARCHIVE_RAR;
    } else if (strcasecmp(ext, ".7z") == 0) {
        return ARCHIVE_7Z;
    }
    
    return ARCHIVE_UNKNOWN;
}

// 分析ZIP文件
static archive_info_t* analyze_zip(const char *filename) {
    int err;
    zip_t *archive = zip_open(filename, ZIP_RDONLY, &err);
    if (!archive) {
        print_error("无法打开ZIP文件: %s", filename);
        return NULL;
    }
    
    archive_info_t *info = calloc(1, sizeof(archive_info_t));
    if (!info) {
        zip_close(archive);
        return NULL;
    }
    
    info->filename = strdup(filename);
    info->type = ARCHIVE_ZIP;
    info->file_count = zip_get_num_entries(archive, 0);
    info->total_size = 0;
    info->is_encrypted = false;
    info->has_fake_encryption = false;
    
    // 检查每个文件条目
    for (zip_uint64_t i = 0; i < info->file_count; i++) {
        zip_stat_t stat;
        if (zip_stat_index(archive, i, 0, &stat) == 0) {
            info->total_size += stat.size;
            
            // 检查加密标志
            if (stat.encryption_method != ZIP_EM_NONE) {
                info->is_encrypted = true;
            }
            
            // 检查伪加密（通过标志位检测）
            zip_file_t *file = zip_fopen_index(archive, i, 0);
            if (!file && zip_get_error(archive)->zip_err == ZIP_ER_WRONGPASSWD) {
                // 尝试读取文件头来检测伪加密
                struct zip_stat st;
                if (zip_stat_index(archive, i, ZIP_FL_UNCHANGED, &st) == 0) {
                    if (st.size > 0 && st.size <= 8 && st.comp_size == st.size) {
                        info->has_fake_encryption = true;
                    }
                }
            } else if (file) {
                zip_fclose(file);
            }
        }
    }
    
    zip_close(archive);
    return info;
}

// 分析RAR文件（使用libarchive）
static archive_info_t* analyze_rar(const char *filename) {
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_rar(a);
    
    if (archive_read_open_filename(a, filename, 10240) != ARCHIVE_OK) {
        print_error("无法打开RAR文件: %s", filename);
        archive_read_free(a);
        return NULL;
    }
    
    archive_info_t *info = calloc(1, sizeof(archive_info_t));
    if (!info) {
        archive_read_free(a);
        return NULL;
    }
    
    info->filename = strdup(filename);
    info->type = ARCHIVE_RAR;
    info->file_count = 0;
    info->total_size = 0;
    info->is_encrypted = false;
    info->has_fake_encryption = false;
    
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        info->file_count++;
        info->total_size += archive_entry_size(entry);
        
        // 检查是否加密
        if (archive_entry_is_encrypted(entry)) {
            info->is_encrypted = true;
        }
        
        archive_read_data_skip(a);
    }
    
    archive_read_free(a);
    return info;
}

// 分析7Z文件（使用libarchive）
static archive_info_t* analyze_7z(const char *filename) {
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_7zip(a);
    
    if (archive_read_open_filename(a, filename, 10240) != ARCHIVE_OK) {
        print_error("无法打开7Z文件: %s", filename);
        archive_read_free(a);
        return NULL;
    }
    
    archive_info_t *info = calloc(1, sizeof(archive_info_t));
    if (!info) {
        archive_read_free(a);
        return NULL;
    }
    
    info->filename = strdup(filename);
    info->type = ARCHIVE_7Z;
    info->file_count = 0;
    info->total_size = 0;
    info->is_encrypted = false;
    info->has_fake_encryption = false;
    
    struct archive_entry *entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        info->file_count++;
        info->total_size += archive_entry_size(entry);
        
        // 检查是否加密
        if (archive_entry_is_encrypted(entry)) {
            info->is_encrypted = true;
        }
        
        archive_read_data_skip(a);
    }
    
    archive_read_free(a);
    return info;
}

// 分析压缩包
archive_info_t* analyze_archive(const char *filename) {
    if (!filename || !file_exists(filename)) {
        return NULL;
    }
    
    archive_type_t type = detect_archive_type(filename);
    
    switch (type) {
        case ARCHIVE_ZIP:
            return analyze_zip(filename);
        case ARCHIVE_RAR:
            return analyze_rar(filename);
        case ARCHIVE_7Z:
            return analyze_7z(filename);
        default:
            print_error("不支持的压缩包格式");
            return NULL;
    }
}

// 检查压缩包是否加密
bool is_archive_encrypted(const char *filename, archive_type_t type) {
    (void)type; // 避免未使用参数警告
    archive_info_t *info = analyze_archive(filename);
    if (!info) return false;
    
    bool encrypted = info->is_encrypted;
    free_archive_info(info);
    return encrypted;
}

// 检查是否有伪加密
bool has_fake_encryption(const char *filename) {
    if (detect_archive_type(filename) != ARCHIVE_ZIP) {
        return false; // 只有ZIP支持伪加密检测
    }
    
    archive_info_t *info = analyze_zip(filename);
    if (!info) return false;
    
    bool fake = info->has_fake_encryption;
    free_archive_info(info);
    return fake;
}

// 修复伪加密
bool fix_fake_encryption(const char *filename, const char *output_filename) {
    if (detect_archive_type(filename) != ARCHIVE_ZIP) {
        return false;
    }
    
    int err;
    zip_t *source = zip_open(filename, ZIP_RDONLY, &err);
    if (!source) {
        return false;
    }
    
    zip_t *dest = zip_open(output_filename, ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!dest) {
        zip_close(source);
        return false;
    }
    
    zip_uint64_t num_entries = zip_get_num_entries(source, 0);
    
    for (zip_uint64_t i = 0; i < num_entries; i++) {
        zip_stat_t stat;
        if (zip_stat_index(source, i, 0, &stat) != 0) {
            continue;
        }
        
        // 读取文件数据
        zip_file_t *file = zip_fopen_index(source, i, 0);
        if (!file) continue;
        
        char *buffer = malloc(stat.size);
        if (!buffer) {
            zip_fclose(file);
            continue;
        }
        
        zip_int64_t bytes_read = zip_fread(file, buffer, stat.size);
        zip_fclose(file);
        
        if (bytes_read > 0) {
            // 创建新的文件条目（移除加密标志）
            zip_source_t *source_data = zip_source_buffer(dest, buffer, bytes_read, 1);
            if (source_data) {
                zip_file_add(dest, stat.name, source_data, ZIP_FL_OVERWRITE);
            }
        } else {
            free(buffer);
        }
    }
    
    zip_close(dest);
    zip_close(source);
    
    return true;
}

// 释放压缩包信息
void free_archive_info(archive_info_t *info) {
    if (info) {
        free(info->filename);
        free(info);
    }
}