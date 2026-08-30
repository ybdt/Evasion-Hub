#include <stdio.h>
#include <stdlib.h>

// --- 配置参数 ---
// 1. 待读取的二进制文件名
#define INPUT_FILENAME "externel-agent-encrypt.bin"

// 2. 输出的 Lua 文件名
#define OUTPUT_FILENAME "externel-output-hex.lua"

// 3. 每行输出的十六进制字节数 (为了美观和可读性，例如设置为 16)
#define BYTES_PER_LINE 16

// 4. Lua table 变量名
#define LUA_TABLE_NAME "file_data"
// --- 配置结束 ---

/**
 * @brief 读取二进制文件并将其内容输出为 Lua table 格式。
 * * @param input_path 输入二进制文件的路径。
 * @param output_path 输出 Lua 文件的路径。
 * @return int 成功返回 0，失败返回 1。
 */
int convert_bin_to_lua(const char* input_path, const char* output_path) {
    FILE* input_file = NULL;
    FILE* output_file = NULL;
    unsigned char* buffer = NULL;
    long file_size = 0;
    size_t bytes_read = 0;
    long i;

    // 1. 打开输入二进制文件 (以二进制读取模式 "rb")
    // MSVC 编译器推荐使用 fopen_s 替代 fopen 以增强安全性
    if (fopen_s(&input_file, input_path, "rb") != 0 || input_file == NULL) {
        fprintf(stderr, "错误: 无法打开输入文件 '%s'。\n", input_path);
        return 1;
    }

    // 2. 获取文件大小
    fseek(input_file, 0, SEEK_END);
    file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "错误: 文件 '%s' 为空或读取大小失败。\n", input_path);
        fclose(input_file);
        return 1;
    }

    // 3. 分配内存并读取整个文件内容
    buffer = (unsigned char*)malloc(file_size);
    if (buffer == NULL) {
        fprintf(stderr, "错误: 内存分配失败。\n");
        fclose(input_file);
        return 1;
    }

    bytes_read = fread(buffer, 1, file_size, input_file);
    fclose(input_file); // 读取完成后关闭输入文件

    if (bytes_read != file_size) {
        fprintf(stderr, "警告: 仅读取了 %zu 字节，预期为 %ld 字节。\n", bytes_read, file_size);
        file_size = bytes_read; // 使用实际读取的大小
    }

    // 4. 打开输出 Lua 文件 (以写入模式 "w")
    if (fopen_s(&output_file, output_path, "w") != 0 || output_file == NULL) {
        fprintf(stderr, "错误: 无法创建输出文件 '%s'。\n", output_path);
        free(buffer);
        return 1;
    }

    // 5. 写入 Lua Table 的头部
    fprintf(output_file, "-- 文件名: %s\n", input_path);
    fprintf(output_file, "-- 大小: %ld 字节\n", file_size);
    fprintf(output_file, "local %s = {\n", LUA_TABLE_NAME);

    // 6. 遍历缓冲区，以十六进制格式写入 Lua table 元素
    for (i = 0; i < file_size; i++) {
        // 写入字节值，格式为 0xXX
        fprintf(output_file, "0x%02X", buffer[i]);

        // 检查是否是最后一个元素
        if (i < file_size - 1) {
            fprintf(output_file, ",");
        }

        // 检查是否需要换行并添加注释
        if ((i + 1) % BYTES_PER_LINE == 0) {
            // 每行末尾添加一个空格和注释，显示当前行的起始字节索引
            fprintf(output_file, " -- 索引 0x%lX\n    ", i - BYTES_PER_LINE + 1);
        }
        else if (i < file_size - 1) {
            // 在同一行内的元素之间添加一个空格
            fprintf(output_file, " ");
        }
    }

    // 7. 写入 Lua Table 的尾部并结束
    fprintf(output_file, "\n}\n\n");
    fprintf(output_file, "return %s\n", LUA_TABLE_NAME);

    // 8. 清理和关闭
    fclose(output_file);
    free(buffer);

    printf("成功!\n");
    printf("已读取文件: '%s' (%ld 字节)\n", input_path, file_size);
    printf("已输出 Lua 文件: '%s'\n", output_path);

    return 0;
}

int main() {
    return convert_bin_to_lua(INPUT_FILENAME, OUTPUT_FILENAME);
}