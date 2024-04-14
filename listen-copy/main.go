package main

import (
	"fmt"
	"log"

	"github.com/mdlayher/netlink"
)

const (
	netlinkUser    = 9988 // 和内核模块中定义的一致
	multicastGroup = 8899 // 和内核模块中定义的一致
)

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

	// 接收消息的循环
	for {
		msgs, err := conn.Receive()
		if err != nil {
			log.Fatalf("failed to receive messages: %v\n", err)
		}

		// 处理接收到的每个消息
		for _, m := range msgs {
			fmt.Printf("Received message: %s\n", string(m.Data))
		}
	}
}
