package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/mdlayher/netlink"
)

const (
	netlinkUser    = 31 // 和内核模块中定义的一致
	multicastGroup = 1  // 和内核模块中定义的一致

	CACHE_PATH     = "/root/local_blocks/"
	NFS_BLOCK_PATH = "/root/tarball/nfs_blocks"
)

func download(key string) error {
	key = key[:len(key)-1]
	blockPath := filepath.Join(CACHE_PATH, key)
	if _, err := os.Stat(blockPath); err == nil {
		return nil
	}

	srcPath := filepath.Join(NFS_BLOCK_PATH, key)
	return copyBetweenNFS(srcPath, blockPath)
}

func copyBetweenNFS(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	}

	dstTmp := dst + "." + uuid.NewString()
	buf, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	dir, _ := filepath.Split(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(dstTmp, buf, 0644); err != nil {
		return err
	}

	return os.Rename(dstTmp, dst)
}

func copy(keyChan <-chan string) {
	for i := 0; i < 30; i++ {
		go func() {
			for key := range keyChan {
				err := download(key)
				if err != nil {
					fmt.Printf("download failed: %v\n", err)
				}
			}
		}()
	}
}

func main() {
	// 创建Netlink配置
	config := &netlink.Config{
		Groups: multicastGroup, // 订阅多播组
	}

	// 创建Netlink连接
	conn, err := netlink.Dial(netlinkUser, config)
	if err != nil {
		log.Fatalf("failed to dial netlink: %v\n", err)
	}
	defer conn.Close()

	// 加入多播组
	err = conn.JoinGroup(multicastGroup)
	if err != nil {
		log.Fatalf("failed to join multicast group: %v\n", err)
	}

	fmt.Printf("Waiting for message from kernel\n")

	keyChan := make(chan string, 1024*1024)
	defer close(keyChan)

	go copy(keyChan)

	// 接收消息的循环
	for {
		msgs, err := conn.Receive()
		if err != nil {
			log.Fatalf("failed to receive messages: %v\n", err)
		}

		// 处理接收到的每个消息
		for _, m := range msgs {
			keyChan <- string(m.Data)
		}
	}
}
