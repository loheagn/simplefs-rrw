#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>


#define BUFFER_SIZE 4096

// 假设我们要读取的内存地址定义为常量，实际场景可能需要从其他方式获取
const char *source_address1 = (const char *) 0x10000000;  // 示例地址1
const char *source_address2 = (const char *) 0x10001000;  // 示例地址2

int mymap(long addr, char *dst, const char *filepath)
{
    int filedes;
    void *map_addr;

    // 打开文件
    filedes = open(filepath, O_RDONLY);
    if (filedes == -1) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    // 计算映射的大小，这里假设我们知道文件大小或者至少映射一个系统页面大小
    size_t map_size = BUFFER_SIZE;  // 假设页面大小是 4096 字节，即0x1000

    // 映射文件
    map_addr = mmap((void *) addr, map_size, PROT_READ, MAP_SHARED | MAP_FIXED,
                    filedes, 3 * 4096);
    if (map_addr == MAP_FAILED) {
        perror("Error mapping file");
        close(filedes);
        return EXIT_FAILURE;
    }

    printf("File '%s' has been mapped at %p\n", filepath, map_addr);

    memcpy(dst, map_addr, BUFFER_SIZE);

    // 使用映射的数据...

    // 解除映射
    if (munmap(map_addr, map_size) == -1) {
        perror("Error unmapping file");
    }

    // 关闭文件
    close(filedes);

    return EXIT_SUCCESS;
}


int main()
{
    char buffer1[BUFFER_SIZE];
    char buffer2[BUFFER_SIZE];

    mymap(0x10000000, buffer1, "/mnt/t1/helloc");
    mymap(0x10001000, buffer2, "/root/testc");

    // 比较两个缓冲区是否相同
    if (memcmp(buffer1, buffer2, BUFFER_SIZE) == 0) {
        printf("The data in the two arrays are identical.\n");
    } else {
        printf("The data in the two arrays are not identical.\n");
    }

    return 0;
}