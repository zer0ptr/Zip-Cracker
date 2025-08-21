# C Zip Cracker Makefile
# 高性能压缩包密码破解工具

# 编译器设置
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -O3 -std=c99 -D_GNU_SOURCE
CXXFLAGS = -Wall -Wextra -O3 -std=c++11
LDFLAGS = -pthread

# 目录设置
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin
LIBDIR = lib

# 目标程序名
TARGET = $(BINDIR)/zip-cracker

# 源文件
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# 库依赖
LIBS = -lzip -larchive -lz -lbz2 -llzma -lcrypto -lssl

# 包含路径
INCLUDES = -I$(INCDIR)

# 检测系统
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LIBS += -lrt
endif
ifeq ($(UNAME_S),Darwin)
    CFLAGS += -I/usr/local/include
    LDFLAGS += -L/usr/local/lib
endif

# 默认目标
all: directories $(TARGET)

# 创建目录
directories:
	@mkdir -p $(OBJDIR) $(BINDIR)

# 链接目标程序
$(TARGET): $(OBJECTS)
	@echo "链接 $@..."
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)
	@echo "构建完成: $@"

# 编译源文件
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@echo "编译 $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 清理
clean:
	@echo "清理构建文件..."
	rm -rf $(OBJDIR) $(BINDIR)

# 安装依赖（Ubuntu/Debian）
install-deps-ubuntu:
	@echo "安装依赖包 (Ubuntu/Debian)..."
	sudo apt-get update
	sudo apt-get install -y build-essential
	sudo apt-get install -y libzip-dev libarchive-dev zlib1g-dev
	sudo apt-get install -y libbz2-dev liblzma-dev libssl-dev
	sudo apt-get install -y pkg-config

# 安装依赖（CentOS/RHEL/Fedora）
install-deps-centos:
	@echo "安装依赖包 (CentOS/RHEL/Fedora)..."
	sudo yum groupinstall -y "Development Tools"
	sudo yum install -y libzip-devel libarchive-devel zlib-devel
	sudo yum install -y bzip2-devel xz-devel openssl-devel
	sudo yum install -y pkgconfig

# 安装依赖（Arch Linux）
install-deps-arch:
	@echo "安装依赖包 (Arch Linux)..."
	sudo pacman -S --needed base-devel
	sudo pacman -S --needed libzip libarchive zlib bzip2 xz openssl
	sudo pacman -S --needed pkgconf

# 安装依赖（macOS）
install-deps-macos:
	@echo "安装依赖包 (macOS)..."
	brew install libzip libarchive zlib bzip2 xz openssl
	brew install pkg-config

# 调试版本
debug: CFLAGS += -g -DDEBUG -O0
debug: directories $(TARGET)

# 发布版本
release: CFLAGS += -DNDEBUG -O3 -march=native
release: directories $(TARGET)

# 静态链接版本
static: LDFLAGS += -static
static: directories $(TARGET)

# 性能分析版本
profile: CFLAGS += -pg -g
profile: LDFLAGS += -pg
profile: directories $(TARGET)

# 内存检查版本
valgrind: CFLAGS += -g -O0 -DDEBUG
valgrind: directories $(TARGET)

# 运行测试
test: $(TARGET)
	@echo "运行测试..."
	@if [ -f "../test01.zip" ]; then \
		./$(TARGET) --help; \
		echo "测试文件: ../test01.zip"; \
	else \
		echo "未找到测试文件 ../test01.zip"; \
	fi

# 安装到系统
install: $(TARGET)
	@echo "安装到系统..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/zip-cracker
	@echo "安装完成: /usr/local/bin/zip-cracker"

# 卸载
uninstall:
	@echo "从系统卸载..."
	sudo rm -f /usr/local/bin/zip-cracker
	@echo "卸载完成"

# 创建发布包
package: release
	@echo "创建发布包..."
	mkdir -p package/zip-cracker
	cp $(TARGET) package/zip-cracker/
	cp README.md package/zip-cracker/ 2>/dev/null || echo "README.md not found"
	cp ../password_list.txt package/zip-cracker/ 2>/dev/null || echo "password_list.txt not found"
	tar -czf zip-cracker-$(shell date +%Y%m%d).tar.gz -C package zip-cracker
	rm -rf package
	@echo "发布包创建完成: zip-cracker-$(shell date +%Y%m%d).tar.gz"

# 代码格式化
format:
	@echo "格式化代码..."
	find $(SRCDIR) $(INCDIR) -name "*.c" -o -name "*.h" | xargs clang-format -i

# 代码检查
lint:
	@echo "代码检查..."
	cppcheck --enable=all --std=c99 $(SRCDIR)/ $(INCDIR)/

# 显示帮助
help:
	@echo "可用目标:"
	@echo "  all              - 构建程序 (默认)"
	@echo "  debug            - 构建调试版本"
	@echo "  release          - 构建发布版本"
	@echo "  static           - 构建静态链接版本"
	@echo "  profile          - 构建性能分析版本"
	@echo "  valgrind         - 构建内存检查版本"
	@echo "  test             - 运行测试"
	@echo "  install          - 安装到系统"
	@echo "  uninstall        - 从系统卸载"
	@echo "  package          - 创建发布包"
	@echo "  clean            - 清理构建文件"
	@echo "  format           - 格式化代码"
	@echo "  lint             - 代码检查"
	@echo "  install-deps-*   - 安装依赖包"
	@echo "    ubuntu         - Ubuntu/Debian"
	@echo "    centos         - CentOS/RHEL/Fedora"
	@echo "    arch           - Arch Linux"
	@echo "    macos          - macOS"

# 显示构建信息
info:
	@echo "构建信息:"
	@echo "  编译器: $(CC)"
	@echo "  编译选项: $(CFLAGS)"
	@echo "  链接选项: $(LDFLAGS)"
	@echo "  库依赖: $(LIBS)"
	@echo "  源文件: $(SOURCES)"
	@echo "  目标文件: $(OBJECTS)"
	@echo "  目标程序: $(TARGET)"

# 伪目标
.PHONY: all clean debug release static profile valgrind test install uninstall
.PHONY: package format lint help info directories
.PHONY: install-deps-ubuntu install-deps-centos install-deps-arch install-deps-macos

# 依赖关系
$(OBJDIR)/main.o: $(INCDIR)/zip_cracker.h
$(OBJDIR)/archive_analyzer.o: $(INCDIR)/zip_cracker.h
$(OBJDIR)/password_generator.o: $(INCDIR)/zip_cracker.h
$(OBJDIR)/crc_cracker.o: $(INCDIR)/zip_cracker.h
$(OBJDIR)/brute_force.o: $(INCDIR)/zip_cracker.h
$(OBJDIR)/thread_pool.o: $(INCDIR)/zip_cracker.h
$(OBJDIR)/utils.o: $(INCDIR)/zip_cracker.h