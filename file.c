#define pr_fmt(fmt) "simplefs: " fmt

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>

#include "bitmap.h"
#include "simplefs.h"

void send_msg_to_user_space(const char *message)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(message) + 1;
    int res;

    // 分配skb
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    // 创建nlmsghdr
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        printk(KERN_ERR "Failed to put nlmsg\n");
        return;
    }

    // 复制消息到netlink消息体中
    strncpy(nlmsg_data(nlh), message, msg_size);

    // 设置控制字段
    NETLINK_CB(skb).dst_group = MULTICAST_GROUP;  // 设置目标多播组

    // 发送消息
    res = nlmsg_multicast(nl_sk, skb, 0, MULTICAST_GROUP, GFP_KERNEL);
    if (res < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}

#define RRW_KEY_LENGTH 32

static struct buffer_head *read_by_iblock(struct inode *inode, sector_t iblock)
{
    struct buffer_head *bh = NULL;
    struct super_block *sb = inode->i_sb;
    // struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct simplefs_file_ei_block *index;
    struct buffer_head *bh_index;
    int ret = 0, bno;
    uint32_t extent;

    /* If block number exceeds filesize, fail */
    if (iblock >= SIMPLEFS_MAX_BLOCKS_PER_EXTENT * SIMPLEFS_MAX_EXTENTS) {
        return NULL;
    }

    /* Read directory block from disk */
    bh_index = sb_bread(sb, ci->ei_block);
    if (!bh_index) {
        return NULL;
    }
    index = (struct simplefs_file_ei_block *) bh_index->b_data;

    extent = simplefs_ext_search(index, iblock);
    if (extent == -1) {
        goto brelse_index;
    }
    bno = index->extents[extent].ee_start + iblock -
          index->extents[extent].ee_block;

    bh = sb_bread(sb, bno);

brelse_index:
    brelse(bh_index);

    return bh;
}

const char hex_table[16] = "0123456789abcdef";

static void hex_encode(char *dst, const char *src)
{
    int j = 0;
    int i = 0;
    for (i = 0; i < 32; i++) {
        unsigned char v = *(src + i);
        dst[j++] = hex_table[v >> 4];
        dst[j++] = hex_table[v & 0xf];
    }
    dst[j] = 0x0;
}

const char *NFS_PATH_PREFIX = "/root/tarball/nfs_blocks/";
const char *LOCAL_PATH_PREFIX = "/root/local_blocks/";

static char *local_path(const char *key)
{
    int len = strlen(key) + strlen(LOCAL_PATH_PREFIX) + 1;
    char *result = kmalloc(len, GFP_KERNEL);

    snprintf(result, len, "%s%s", LOCAL_PATH_PREFIX, key);
    return result;
}

static char *nfs_path(const char *key)
{
    int len = strlen(key) + strlen(NFS_PATH_PREFIX) + 1;
    char *result = kmalloc(len, GFP_KERNEL);

    snprintf(result, len, "%s%s", NFS_PATH_PREFIX, key);
    return result;
}

static void my_custom_readahead(struct readahead_control *rac)
{
    struct inode *inode = rac->file->f_inode;
    // static const char *src = "Hello, this is sample data from kernel space!";
    // static const loff_t data_size = 44;  // 长度包括末尾的'\0'
    // pr_info("loheagn get into");
    // loff_t data_size = 11;
    // loff_t pos = readahead_pos(rac);                // 文件中的起始位置
    unsigned long index = readahead_index(rac);     // 起始页索引
    unsigned long nr_pages = readahead_count(rac);  // 预读页数

    unsigned long chunk_pre_block = PAGE_SIZE / RRW_KEY_LENGTH;

    unsigned long iblock = index / chunk_pre_block;

    struct buffer_head *bh = NULL;
    char *keys = NULL;

    unsigned long i = 0;

    // pr_info("loheagn try to read iblock %d", iblock);
    bh = read_by_iblock(inode, iblock);
    if (!bh) {
        // pr_info("loheagn get into bh null");
        return;
    }
    keys = (char *) bh->b_data;

    char *file_path = NULL;

    // 遍历所有需要读取的页
    for (i = 0; i < nr_pages; i++, index++) {
        // pr_info("loheagn get into for i %d", i);
        struct page *page = readahead_page(rac);  // 获取一个新的页
        char *page_data;
        if (!page)
            continue;

        // 获取页内部的数据地址
        page_data = kmap(page);

        // pr_info("loheagn got page data");

        unsigned long chunk_idx = index;  // 要读第几个chunk

        if (chunk_idx >= (iblock + 1) * chunk_pre_block) {
            iblock++;
            if (bh) {
                brelse(bh);
            }

            // pr_info("loheagn try to read iblock %d", iblock);
            bh = read_by_iblock(inode, iblock);
            keys = (char *) bh->b_data;
        }

        char key[65];

        hex_encode(key, keys + (chunk_idx % chunk_pre_block) * RRW_KEY_LENGTH);

        // pr_info("loheagn chunk_idx %d key %s", chunk_idx, key);

        file_path = local_path(key);

        struct path path;
        if (kern_path(file_path, 0, &path)) {
            // file not exist
            kfree(file_path);
            file_path = nfs_path(key);
            send_msg_to_user_space(key);
        } else {
            // file exists, release path
            path_put(&path);
        }

        struct file *f = filp_open(file_path, O_RDONLY, 0);
        if (IS_ERR_OR_NULL(f)) {
            printk(KERN_ERR "loheagn3 Failed to open file %s\n", file_path);
            goto end;
        }

        size_t length = PAGE_SIZE;
        if (length > f->f_inode->i_size) {
            length = f->f_inode->i_size;
        }
        // pr_info("loheagn length %d", length);

        loff_t offset = 0;
        kernel_read(f, page_data, length, &offset);

        filp_close(f, NULL);

        if (file_path) {
            kfree(file_path);
            file_path = NULL;
        }

        // 清零剩余部分
        if (length < PAGE_SIZE) {
            memset(page_data + length, 0, PAGE_SIZE - length);
        }

        // pr_info("loheagn copy done length %d", length);

        // 解除页的映射
        kunmap(page);

        // 将页标记为已更新并解锁
        SetPageUptodate(page);
        unlock_page(page);

        // 将页放入页缓存
        put_page(page);

        // pr_info("loheagn end for length %d", length);
    }

end:

    if (file_path) {
        kfree(file_path);
    }

    if (bh) {
        brelse(bh);
    }
}

static int my_custom_readpage(struct file *file, struct page *page)
{
    struct inode *inode = file->f_inode;
    unsigned long index = page->index;

    unsigned long chunk_pre_block = PAGE_SIZE / RRW_KEY_LENGTH;

    unsigned long iblock = index / chunk_pre_block;

    struct buffer_head *bh = NULL;
    char *keys = NULL;

    // pr_info("loheagn try to read iblock %d", iblock);
    bh = read_by_iblock(inode, iblock);
    if (!bh) {
        // pr_info("loheagn get into bh null");
        return 0;
    }
    keys = (char *) bh->b_data;

    char *file_path = NULL;

    char *page_data = kmap(page);

    // pr_info("loheagn got page data");

    unsigned long chunk_idx = index;  // 要读第几个chunk

    char key[65];

    hex_encode(key, keys + (chunk_idx % chunk_pre_block) * RRW_KEY_LENGTH);

    pr_info("loheagn chunk_idx %d key %s", chunk_idx, key);

    file_path = local_path(key);

    struct path path;
    if (kern_path(file_path, 0, &path)) {
        // file not exist
        kfree(file_path);
        file_path = nfs_path(key);
    } else {
        // file exists, release path
        path_put(&path);
    }

    struct file *f = filp_open(file_path, O_RDONLY, 0);
    if (IS_ERR_OR_NULL(f)) {
        printk(KERN_ERR "loheagn3 Failed to open file %s\n", file_path);
        goto end;
    }

    size_t length = PAGE_SIZE;
    if (length > f->f_inode->i_size) {
        length = f->f_inode->i_size;
    }
    // pr_info("loheagn length %d", length);

    loff_t offset = 0;
    kernel_read(f, page_data, length, &offset);

    filp_close(f, NULL);

    if (file_path) {
        kfree(file_path);
        file_path = NULL;
    }

    // 清零剩余部分
    if (length < PAGE_SIZE) {
        memset(page_data + length, 0, PAGE_SIZE - length);
    }

    // pr_info("loheagn copy done length %d", length);

    // 解除页的映射
    kunmap(page);

    // 将页标记为已更新并解锁
    SetPageUptodate(page);
    unlock_page(page);

    // 将页放入页缓存
    put_page(page);

end:

    if (file_path) {
        kfree(file_path);
    }

    if (bh) {
        brelse(bh);
    }

    return 0;
}


// 自定义的页面错误处理函数
static vm_fault_t myfs_vm_fault(struct vm_fault *vmf)
{
    struct file *file;
    struct page *page;
    struct inode *inode;
    loff_t file_size, offset;
    char *page_addr;
    ssize_t read_bytes;


    // find the chunk file
    unsigned long index = vmf->pgoff;
    unsigned long chunk_pre_block = PAGE_SIZE / RRW_KEY_LENGTH;
    unsigned long iblock = index / chunk_pre_block;

    struct file *this_file = vmf->vma->vm_file;
    struct inode *this_inode = this_file->f_inode;
    struct buffer_head *bh = read_by_iblock(this_inode, iblock);
    if (!bh) {
        return VM_FAULT_SIGBUS;
    }

    char *keys = (char *) bh->b_data;
    char key[65];
    hex_encode(key, keys + (index % chunk_pre_block) * RRW_KEY_LENGTH);

    brelse(bh);

    char *file_path = local_path(key);

    struct path path;
    if (kern_path(file_path, 0, &path)) {
        // file not exist
        kfree(file_path);
        file_path = nfs_path(key);
    } else {
        // file exists, release path
        path_put(&path);
    }

    file = filp_open(file_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        return VM_FAULT_SIGBUS;
    }

    kfree(file_path);

    // 获取一个新的页面
    page = alloc_page(GFP_KERNEL);
    if (!page) {
        filp_close(file, 0);
        return VM_FAULT_OOM;
    }

    // 填充页面内容
    page_addr = kmap(page);
    offset = 0;
    read_bytes = kernel_read(file, page_addr, PAGE_SIZE, &offset);
    pr_info("loheagn read %d bytes for page %d", read_bytes, index);
    if (read_bytes < PAGE_SIZE) {
        // 文件剩余内容可能小于一个页面大小或读取发生错误
        clear_highpage(page);
        if (read_bytes > 0) {
            // 复制实际读取到的字节
            memcpy(page_addr, page_addr, read_bytes);
        }
    }
    // pr_info("loheagn 1");
    kunmap(page);
    // pr_info("loheagn 2");
    // 取消对文件的引用
    filp_close(file, 0);
    // pr_info("loheagn 3");

    // 将读取到的页面插入到线性区域
    // if (vm_insert_page(vmf->vma, vmf->address, page)) {
    //     // 在失败的情况下释放页面并返回错误
    //     pr_info("loheagn 4");
    //     __free_pages(page, 0);
    //     return VM_FAULT_SIGBUS;
    // }
    vmf->page = page;
    // pr_info("loheagn 5");

    // 标记页面为脏，如果它被写入的话
    set_page_dirty_lock(page);

    // pr_info("loheagn 6");
    return 0;

    // return VM_FAULT_NOPAGE;  // 或者其他适当的 vm_fault_t 返回值
}

// 自定义的 vm_operations_struct
static const struct vm_operations_struct myfs_vm_ops = {
    .fault = myfs_vm_fault,
};


// 文件系统中的 mmap 方法的一个简单示例
static int myfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    // 确认 VMA 是有效的，而且可以被 mmap
    if (vma->vm_start & (~PAGE_MASK))
        return -ENXIO;

    // 设置自定义的 fault 处理函数，自行实现
    // vma->vm_flags |= VM_IO;
    vma->vm_ops = &myfs_vm_ops;

    return 0;
}

/* Associate the provided 'buffer_head' parameter with the iblock-th block of
 * the file denoted by inode. Should the specified block be unallocated and the
 * create flag is set to true, proceed to allocate a new block on the disk and
 * establish a mapping for it.
 */
static int simplefs_file_get_block(struct inode *inode,
                                   sector_t iblock,
                                   struct buffer_head *bh_result,
                                   int create)
{
    struct super_block *sb = inode->i_sb;
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct simplefs_file_ei_block *index;
    struct buffer_head *bh_index;
    int ret = 0, bno;
    uint32_t extent;

    /* If block number exceeds filesize, fail */
    if (iblock >= SIMPLEFS_MAX_BLOCKS_PER_EXTENT * SIMPLEFS_MAX_EXTENTS)
        return -EFBIG;

    /* Read directory block from disk */
    bh_index = sb_bread(sb, ci->ei_block);
    if (!bh_index)
        return -EIO;
    index = (struct simplefs_file_ei_block *) bh_index->b_data;

    extent = simplefs_ext_search(index, iblock);
    if (extent == -1) {
        ret = -EFBIG;
        goto brelse_index;
    }

    /* Determine whether the 'iblock' is currently allocated. If it is not and
     * the create parameter is set to true, then allocate the block. Otherwise,
     * retrieve the physical block number.
     */
    if (index->extents[extent].ee_start == 0) {
        if (!create) {
            ret = 0;
            goto brelse_index;
        }
        bno = get_free_blocks(sbi, 8);
        if (!bno) {
            ret = -ENOSPC;
            goto brelse_index;
        }

        index->extents[extent].ee_start = bno;
        index->extents[extent].ee_len = 8;
        index->extents[extent].ee_block =
            extent ? index->extents[extent - 1].ee_block +
                         index->extents[extent - 1].ee_len
                   : 0;
    } else {
        bno = index->extents[extent].ee_start + iblock -
              index->extents[extent].ee_block;
    }

    /* Map the physical block to the given 'buffer_head'. */
    map_bh(bh_result, sb, bno);

brelse_index:
    brelse(bh_index);

    return ret;
}

/* Called by the page cache to read a page from the physical disk and map it
 * into memory.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
static void simplefs_readahead(struct readahead_control *rac)
{
    mpage_readahead(rac, simplefs_file_get_block);
}
#else
static int simplefs_readpage(struct file *file, struct page *page)
{
    return mpage_readpage(page, simplefs_file_get_block);
}
#endif

/* Called by the page cache to write a dirty page to the physical disk (when
 * sync is called or when memory is needed).
 */
static int simplefs_writepage(struct page *page, struct writeback_control *wbc)
{
    return block_write_full_page(page, simplefs_file_get_block, wbc);
}

/* Called by the VFS when a write() syscall is made on a file, before writing
 * the data into the page cache. This function checks if the write operation
 * can complete and allocates the necessary blocks through block_write_begin().
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
static int simplefs_write_begin(struct file *file,
                                struct address_space *mapping,
                                loff_t pos,
                                unsigned int len,
                                struct page **pagep,
                                void **fsdata)
#else
static int simplefs_write_begin(struct file *file,
                                struct address_space *mapping,
                                loff_t pos,
                                unsigned int len,
                                unsigned int flags,
                                struct page **pagep,
                                void **fsdata)
#endif
{
    struct simplefs_sb_info *sbi = SIMPLEFS_SB(file->f_inode->i_sb);
    int err;
    uint32_t nr_allocs = 0;

    /* Check if the write can be completed (enough space?) */
    if (pos + len > SIMPLEFS_MAX_FILESIZE)
        return -ENOSPC;

    nr_allocs = max(pos + len, file->f_inode->i_size) / SIMPLEFS_BLOCK_SIZE;
    if (nr_allocs > file->f_inode->i_blocks - 1)
        nr_allocs -= file->f_inode->i_blocks - 1;
    else
        nr_allocs = 0;
    if (nr_allocs > sbi->nr_free_blocks)
        return -ENOSPC;

        /* prepare the write */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
    err = block_write_begin(mapping, pos, len, pagep, simplefs_file_get_block);
#else
    err = block_write_begin(mapping, pos, len, flags, pagep,
                            simplefs_file_get_block);
#endif
    /* if this failed, reclaim newly allocated blocks */
    if (err < 0)
        pr_err("newly allocated blocks reclaim not implemented yet\n");
    return err;
}

/* Called by the VFS after writing data from a write() syscall to the page
 * cache. This function updates inode metadata and truncates the file if
 * necessary.
 */
static int simplefs_write_end(struct file *file,
                              struct address_space *mapping,
                              loff_t pos,
                              unsigned int len,
                              unsigned int copied,
                              struct page *page,
                              void *fsdata)
{
    struct inode *inode = file->f_inode;
    struct simplefs_inode_info *ci = SIMPLEFS_INODE(inode);
    struct super_block *sb = inode->i_sb;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    struct timespec64 cur_time;
#endif
    uint32_t nr_blocks_old;

    /* Complete the write() */
    int ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
    if (ret < len) {
        pr_err("wrote less than requested.");
        return ret;
    }

    nr_blocks_old = inode->i_blocks;

    /* Update inode metadata */
    inode->i_blocks = inode->i_size / SIMPLEFS_BLOCK_SIZE + 2;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    cur_time = current_time(inode);
    inode->i_mtime = cur_time;
    inode_set_ctime_to_ts(inode, cur_time);
#else
    inode->i_mtime = inode->i_ctime = current_time(inode);
#endif

    mark_inode_dirty(inode);

    /* If file is smaller than before, free unused blocks */
    if (nr_blocks_old > inode->i_blocks) {
        int i;
        struct buffer_head *bh_index;
        struct simplefs_file_ei_block *index;
        uint32_t first_ext;

        /* Free unused blocks from page cache */
        truncate_pagecache(inode, inode->i_size);

        /* Read ei_block to remove unused blocks */
        bh_index = sb_bread(sb, ci->ei_block);
        if (!bh_index) {
            pr_err("failed truncating '%s'. we just lost %llu blocks\n",
                   file->f_path.dentry->d_name.name,
                   nr_blocks_old - inode->i_blocks);
            goto end;
        }
        index = (struct simplefs_file_ei_block *) bh_index->b_data;

        first_ext = simplefs_ext_search(index, inode->i_blocks - 1);

        /* Reserve unused block in last extent */
        if (inode->i_blocks - 1 != index->extents[first_ext].ee_block)
            first_ext++;

        for (i = first_ext; i < SIMPLEFS_MAX_EXTENTS; i++) {
            if (!index->extents[i].ee_start)
                break;
            put_blocks(SIMPLEFS_SB(sb), index->extents[i].ee_start,
                       index->extents[i].ee_len);
            memset(&index->extents[i], 0, sizeof(struct simplefs_extent));
        }
        mark_buffer_dirty(bh_index);
        brelse(bh_index);
    }
end:
    return ret;
}

const struct address_space_operations simplefs_aops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
    // .readahead = simplefs_readahead,
    .readahead = my_custom_readahead,
#else
    .readpage = my_custom_readpage,
#endif
    .writepage = simplefs_writepage,
    .write_begin = simplefs_write_begin,
    .write_end = simplefs_write_end,
};

const struct file_operations simplefs_file_ops = {
    .mmap = myfs_mmap,
    .llseek = generic_file_llseek,
    .owner = THIS_MODULE,
    .read_iter = generic_file_read_iter,
    .write_iter = generic_file_write_iter,
    .fsync = generic_file_fsync,
};
