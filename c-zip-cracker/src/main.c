#include "../include/zip_cracker.h"
#include <getopt.h>
#include <signal.h>

// 全局变量用于信号处理
static thread_pool_t *g_thread_pool = NULL;

// 信号处理函数
void signal_handler(int sig) {
    if (g_thread_pool) {
        printf("\n[!] 收到中断信号，正在停止攻击...\n");
        stop_attack(g_thread_pool);
    }
    exit(0);
}

void print_usage(const char *program_name) {
    printf("用法: %s [选项] <压缩包文件>\n", program_name);
    printf("\n选项:\n");
    printf("  -d, --dict <文件>     指定字典文件 (默认: password_list.txt)\n");
    printf("  -t, --threads <数量>  指定线程数 (默认: CPU核心数 * 4)\n");
    printf("  -m, --mode <模式>     攻击模式: dict|brute|crc|hybrid (默认: hybrid)\n");
    printf("  -o, --output <目录>   解压输出目录 (默认: ./extracted)\n");
    printf("  -h, --help           显示此帮助信息\n");
    printf("\n支持的压缩包格式:\n");
    printf("  - ZIP (.zip)\n");
    printf("  - RAR (.rar)\n");
    printf("  - 7-Zip (.7z)\n");
    printf("\n示例:\n");
    printf("  %s target.zip\n", program_name);
    printf("  %s -d mydict.txt -t 8 target.zip\n", program_name);
    printf("  %s -m crc target.zip\n", program_name);
}

attack_mode_t parse_attack_mode(const char *mode_str) {
    if (strcmp(mode_str, "dict") == 0) {
        return ATTACK_DICTIONARY;
    } else if (strcmp(mode_str, "brute") == 0) {
        return ATTACK_BRUTEFORCE;
    } else if (strcmp(mode_str, "crc") == 0) {
        return ATTACK_CRC32;
    } else if (strcmp(mode_str, "hybrid") == 0) {
        return ATTACK_HYBRID;
    } else {
        return ATTACK_HYBRID; // 默认模式
    }
}

int main(int argc, char *argv[]) {
    // 默认参数
    char *dict_file = "password_list.txt";
    char *output_dir = "./extracted";
    char *target_file = NULL;
    int thread_count = get_cpu_count() * 4;
    attack_mode_t mode = ATTACK_HYBRID;
    
    // 命令行参数解析
    static struct option long_options[] = {
        {"dict", required_argument, 0, 'd'},
        {"threads", required_argument, 0, 't'},
        {"mode", required_argument, 0, 'm'},
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "d:t:m:o:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                dict_file = optarg;
                break;
            case 't':
                thread_count = atoi(optarg);
                if (thread_count <= 0) {
                    print_error("线程数必须大于0");
                    return 1;
                }
                break;
            case 'm':
                mode = parse_attack_mode(optarg);
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // 检查目标文件参数
    if (optind >= argc) {
        print_error("请指定目标压缩包文件");
        print_usage(argv[0]);
        return 1;
    }
    
    target_file = argv[optind];
    
    // 显示横幅
    print_banner();
    
    // 检查文件是否存在
    if (!file_exists(target_file)) {
        print_error("文件不存在: %s", target_file);
        return 1;
    }
    
    // 检查字典文件
    if (mode == ATTACK_DICTIONARY || mode == ATTACK_HYBRID) {
        if (!file_exists(dict_file)) {
            print_error("字典文件不存在: %s", dict_file);
            return 1;
        }
    }
    
    // 分析压缩包
    print_info("正在分析压缩包: %s", target_file);
    archive_info_t *info = analyze_archive(target_file);
    if (!info) {
        print_error("无法分析压缩包文件");
        return 1;
    }
    
    print_info("压缩包类型: %s", 
               info->type == ARCHIVE_ZIP ? "ZIP" :
               info->type == ARCHIVE_RAR ? "RAR" :
               info->type == ARCHIVE_7Z ? "7-Zip" : "未知");
    print_info("文件数量: %u", info->file_count);
    print_info("总大小: %lu 字节", info->total_size);
    
    // 检查加密状态
    if (!info->is_encrypted) {
        print_success("压缩包未加密，可以直接解压");
        // TODO: 直接解压
        free_archive_info(info);
        return 0;
    }
    
    print_info("压缩包已加密");
    
    // 检查伪加密
    if (info->has_fake_encryption) {
        print_info("检测到伪加密，正在修复...");
        char fixed_filename[256];
        snprintf(fixed_filename, sizeof(fixed_filename), "fixed_%s", target_file);
        if (fix_fake_encryption(target_file, fixed_filename)) {
            print_success("伪加密修复完成: %s", fixed_filename);
            free_archive_info(info);
            return 0;
        } else {
            print_error("伪加密修复失败");
        }
    }
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 创建线程池并开始攻击
    print_info("开始密码攻击...");
    print_info("攻击模式: %s", 
               mode == ATTACK_DICTIONARY ? "字典攻击" :
               mode == ATTACK_BRUTEFORCE ? "暴力破解" :
               mode == ATTACK_CRC32 ? "CRC32攻击" : "混合攻击");
    print_info("使用线程数: %d", thread_count);
    
    g_thread_pool = create_thread_pool(thread_count, target_file, dict_file, mode);
    if (!g_thread_pool) {
        print_error("创建线程池失败");
        free_archive_info(info);
        return 1;
    }
    
    start_attack(g_thread_pool);
    
    // 清理资源
    free_thread_pool(g_thread_pool);
    free_archive_info(info);
    
    return 0;
}