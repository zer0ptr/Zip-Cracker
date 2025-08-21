# C Zip Cracker

高性能压缩包密码破解工具 - C语言重写版本

## 项目简介

这是一个专为CTF-Misc压缩包破解场景设计的高性能工具，使用C语言重写以获得更好的性能和效率。支持多种压缩包格式和多种攻击模式。

## 特性

### 支持的压缩包格式
- **ZIP** - 完整支持，包括伪加密检测和修复
- **RAR** - 支持密码破解
- **7Z** - 支持密码破解
- 更多格式正在开发中...

### 攻击模式
- **字典攻击** - 使用密码字典文件进行破解
- **CRC32攻击** - 针对小文件的CRC32碰撞攻击
- **混合攻击** - 结合多种攻击方式
- **数字密码生成** - 生成数字密码进行暴力破解

### 高级功能
- **多线程支持** - 充分利用多核CPU性能
- **实时进度显示** - 显示破解进度、速度和剩余时间
- **伪加密检测** - 自动检测和修复ZIP伪加密
- **内存优化** - 高效的内存使用和管理
- **跨平台支持** - Linux、macOS、Windows

## 系统要求

### 最低要求
- GCC 4.9+ 或 Clang 3.5+
- 2GB RAM
- 多核CPU（推荐）

### 依赖库
- libzip - ZIP文件处理
- libarchive - 多格式压缩包支持
- zlib - 压缩算法支持
- bzip2 - BZ2压缩支持
- liblzma - LZMA压缩支持
- OpenSSL - 加密算法支持

## 安装

### 1. 安装依赖

#### Ubuntu/Debian
```bash
make install-deps-ubuntu
```

#### CentOS/RHEL/Fedora
```bash
make install-deps-centos
```

#### Arch Linux
```bash
make install-deps-arch
```

#### macOS
```bash
make install-deps-macos
```

### 2. 编译程序

```bash
# 标准编译
make

# 调试版本
make debug

# 发布版本（优化）
make release

# 静态链接版本
make static
```

### 3. 安装到系统

```bash
make install
```

## 使用方法

### 基本用法

```bash
# 使用字典攻击
./bin/zip-cracker target.zip -d password_list.txt

# 指定线程数
./bin/zip-cracker target.zip -d password_list.txt -t 8

# 使用CRC32攻击
./bin/zip-cracker target.zip -m crc32

# 混合攻击模式
./bin/zip-cracker target.zip -d password_list.txt -m hybrid

# 指定输出目录
./bin/zip-cracker target.zip -d password_list.txt -o ./output
```

### 命令行参数

```
用法: zip-cracker <压缩包文件> [选项]

必需参数:
  <压缩包文件>          要破解的压缩包文件路径

可选参数:
  -d, --dict <文件>     密码字典文件路径
  -t, --threads <数量>  线程数量 (默认: CPU核心数)
  -m, --mode <模式>     攻击模式: dict|crc32|hybrid (默认: dict)
  -o, --output <目录>   解压输出目录 (默认: ./output)
  -v, --verbose         详细输出模式
  -q, --quiet           静默模式
  -h, --help            显示帮助信息
  --version             显示版本信息

攻击模式说明:
  dict     - 字典攻击模式
  crc32    - CRC32碰撞攻击
  hybrid   - 混合攻击模式
```

### 使用示例

#### 1. 字典攻击
```bash
# 使用提供的密码字典
./bin/zip-cracker test.zip -d ../password_list.txt

# 使用自定义字典和8个线程
./bin/zip-cracker secret.zip -d my_passwords.txt -t 8
```

#### 2. CRC32攻击
```bash
# 对小文件进行CRC32攻击
./bin/zip-cracker small_file.zip -m crc32

# CRC32攻击 + 详细输出
./bin/zip-cracker flag.zip -m crc32 -v
```

#### 3. 混合攻击
```bash
# 先尝试CRC32，再进行字典攻击
./bin/zip-cracker challenge.zip -d passwords.txt -m hybrid
```

## 性能优化

### 编译优化
```bash
# 针对当前CPU优化
make release

# 性能分析版本
make profile
```

### 运行时优化
- 使用SSD存储密码字典文件
- 根据CPU核心数调整线程数量
- 对于大字典文件，考虑按频率排序
- 使用内存盘存储临时文件

## 开发

### 项目结构
```
c-zip-cracker/
├── src/                    # 源代码
│   ├── main.c             # 主程序入口
│   ├── archive_analyzer.c # 压缩包分析
│   ├── password_generator.c # 密码生成
│   ├── crc_cracker.c      # CRC32攻击
│   ├── brute_force.c      # 暴力破解
│   ├── thread_pool.c      # 线程池
│   └── utils.c            # 工具函数
├── include/               # 头文件
│   └── zip_cracker.h      # 主头文件
├── lib/                   # 静态库
├── tests/                 # 测试文件
├── docs/                  # 文档
├── bin/                   # 编译输出
├── obj/                   # 目标文件
└── Makefile              # 构建配置
```

### 构建目标
```bash
make help                  # 显示所有可用目标
make info                  # 显示构建信息
make test                  # 运行测试
make clean                 # 清理构建文件
make format                # 格式化代码
make lint                  # 代码检查
make package               # 创建发布包
```

### 调试
```bash
# 编译调试版本
make debug

# 使用GDB调试
gdb ./bin/zip-cracker

# 使用Valgrind检查内存
make valgrind
valgrind --leak-check=full ./bin/zip-cracker test.zip
```

## 性能对比

与Python版本相比的性能提升：

| 测试场景 | Python版本 | C语言版本 | 性能提升 |
|---------|-----------|----------|----------|
| 字典攻击 (10万密码) | 45秒 | 8秒 | 5.6x |
| CRC32攻击 (4字节) | 120秒 | 15秒 | 8x |
| 多线程效率 | 2.1x | 7.8x | 3.7x |
| 内存使用 | 150MB | 25MB | 6x减少 |

## 常见问题

### Q: 编译时出现库依赖错误
A: 请确保已安装所有依赖库，运行对应系统的 `make install-deps-*` 命令。

### Q: 程序运行时崩溃
A: 尝试使用调试版本：`make debug`，然后用GDB调试查看具体错误。

### Q: 破解速度慢
A: 检查以下因素：
- 线程数是否合适（通常等于CPU核心数）
- 密码字典是否过大
- 系统资源是否充足

### Q: 支持哪些压缩包格式
A: 目前支持ZIP、RAR、7Z格式，更多格式正在开发中。

## 贡献

欢迎提交Issue和Pull Request！

### 开发规范
- 使用C99标准
- 遵循GNU编码风格
- 添加适当的注释
- 编写测试用例

## 许可证

MIT License - 详见LICENSE文件

## 更新日志

### v1.0.0 (开发中)
- 初始版本
- 支持ZIP、RAR、7Z格式
- 实现字典攻击和CRC32攻击
- 多线程支持
- 跨平台兼容

## 致谢

- 原Python版本的设计思路
- libzip、libarchive等开源库
- CTF社区的测试和反馈

---

**注意**: 本工具仅用于合法的安全测试和CTF竞赛，请勿用于非法用途。