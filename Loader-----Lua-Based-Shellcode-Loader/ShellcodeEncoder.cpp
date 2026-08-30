#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

void Xor(char* data, size_t data_len, char* key, size_t key_len)
{
    for (size_t i = 0; i < data_len; i++)
    {
        data[i] ^= key[i % key_len];
    }
}

std::vector<char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Open file error: " + filename);
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    file.read(buffer.data(), size);
    file.close();

    return buffer;
}

void writeFile(const std::string& filename, const std::vector<char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("无法创建文件: " + filename);
    }

    file.write(data.data(), data.size());
    file.close();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <Input File> <Output File>" << std::endl;
        return -1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    char key[] = "key";
    size_t key_len = strlen(key);

    std::vector<char> bin_data = readFile(input_file);
    std::vector<char> bin_data_2 = bin_data;
    std::cout << "File " << input_file << ": " << bin_data.size() << " Byte" << std::endl;

    Xor(bin_data.data(), bin_data.size(), key, key_len);

    writeFile(output_file, bin_data);

    std::vector<char> encoded_bin_data = readFile(output_file);
    Xor(encoded_bin_data.data(), encoded_bin_data.size(), key, key_len);
    if (encoded_bin_data == bin_data_2)
    {
        std::cout << "[+] Encrypt success." << std::endl;
    }
    else
    {
        std::cout << "[-] Encrypt fail." << std::endl;
    }

    return 0;
}