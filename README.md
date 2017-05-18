# MACVLAN 配置工具（mvconf）使用说明

[TOC]

## 1. 简介

mvconf 是一个命令行工具，旨在帮助用户方便的配置 DCE 集群上服务的 MACVLAN。

> mvconf 不提供监控功能，如果想要更完整的体验请使用 DCE 静态 IP 模块。


## 2. 安装

### 2.1 从源码安装

```bash
cd mvconf
pip install -U setuptools
python setup.py install
```

### 2.2 安装二进制可执行程序

```bash
cp mvconf /usr/bin/mvconf
```


## 3. 快速开始
mvconf 可以在任何能访问到 DCE 控制器的机器上运行。

在命令行执行 `mvconf --help` 可以看到简单的命令说明：

```bash
~# mvconf --help    
Usage: mvconf [OPTIONS] COMMAND [ARGS]...

  Create, Bind Network to each container in Service <For DCE SPD Bank>

Options:
  -f, --config-file PATH  config file location, default: ./conf.json
  --version               Show the version and exit.
  --help                  Show this message and exit.

Commands:
  config      Check config file.
  disconnect  Disconnect service from networks.
  down        Disconnect service from and remove networks.
  login       Login to DCE and save auth to ~/.dce_auth
  reingress   Reconnect containers to ingress.
  rm          Remove networks from each node.
  status      Show macvlan status.
  uningress   Disconnect containers from ingress.
  up          Create networks and connect service to it.
```

阅读帮助我们知道可以通过 `mvconf [-f 配置文件] 命令 [命令选项]` 的方式来使用 mvconf。

使用参数 `mvconf 命令 --help` 可以看到命令的帮助，如：

```
~# mvconf status --help
Usage: mvconf status [OPTIONS]

  Show macvlan status.

Options:
  --trunc / --no-trunc  Whether to truncate output
  --sort TEXT           Field to sort by, if has multiple fields separated by
                        comma like 'host_ip,hostname'
  --field TEXT          Field to display, if has multiple fields separated by
                        comma like 'host_ip,hostname'
  --help                Show this message and exit.

```

## 4. DCE 授权

mvconf 需要用到 DCE 管理员权限，在使用的时候我们有两种方式进行授权。

> 在控制节点运行且 DCE 匿名用户可访问时 mvconf 会自动检测无需授权。

### 4.1 使用 `mvconf login` 授权

我们可以像使用 `docker login` 一样使用 `mvconf login DCE控制器IP地址` 来登录 DCE，登陆成功后授权记录默认会保存在 `~/.dce_auth` 文件中。

### 4.2 使用配置文件中的授权

在配置文件中添加 `auth` 字段：

```json
{
  "auth": {
    "url": "192.168.56.102",  // DCE 控制器 IP 地址
    "username": "admin",      // 管理员账号
    "password": "admin"		  // 管理员密码
  }
}
```
> mvconf 会优先读取配置文件中的授权信息。
> 在控制节点运行 mvconf 时会自动检测控制节点 URL，无需填写。

## 5. 配置文件
mvconf 对 MACVLAN 和服务的操作全部依赖于配置文件，配置文件是标准 JSON 文件。

mvconf 默认会读取当前目录下的 `conf.json` 文件，也可使用 `-f 路径` 来指定配置文件路径。

```json
{
  "networks": [                           // MACVLAN 网络配置
    {
      "name": "macvlan",				  // 网络名称
      "subnet": "192.168.8.0/24",         // 网段
      "gateway": "192.168.8.1",           // 网关
      "parent": "eth1",                   // 绑定网卡
      "ip_range": "192.168.8.0/24"        // 可分配 IP 段【可不填】
    }
  ],
  "services": [                           // 要操作的服务
    {
      "name": "2048",                     // 服务名
      "network": "macvlan",               // MACVLAN 网络名
      "ip_pool": [                        // IP 池
        "192.168.8.136-192.168.8.137",
        "192.168.8.139"
      ]
    }
  ],
  "auth": {
    "url": "192.168.56.102",              // DCE 控制器 IP 地址
    "username": "admin",                  // 管理员账号
    "password": "admin"		              // 管理员密码
  }
}
```

### 5.1 网络配置

1. 一个配置文件中网络可以填写多个，也可以不填写
2. 在使用 `mvconf up` 的时候会读取所有 MACVLAN 网络配置，并尝试在每一台主机上创建这些网络
3. 在使用 `mvconf rm` 和 `mvconf down` 时会读取网络名称，并尝试在每一台主机上删除这些网络
4. 网段使用标准 CIDR 格式
5. 如果填写 `ip_range`，则必须是 `subnet` 的子网段
6. `parent` 为 MACVLAN 使用的网卡，通常为主机连接集群内网的网卡，如果网关要求 VLAN ID 则需要配置为带 VLAN ID 的网卡 (docker network create -d macvlan --subnet=192.168.101.0/16 --gateway=192.168.1.1 -o parent=eno16780032 xxx)
7. 宿主机 ping 自身上的 MACVLAN 容器地址，无法 ping 通 (所以，如果有作为负载的 nginx 需要放在其他位置，或者放 nginx 的主机不配置 MACVLAN，还有个办法就是将 nginx 也放入 MACVLAN）
8. 宿主机 ping 其他宿主机上的 MACVLAN 容器地址，可以 ping 通
9. 交换机上有配置是否允许混杂模式的配置，即 Mac 地址对应唯一的物理端口，需要打开。
10. 网卡需要支持 混杂模式
11. 同一个网关地址只能有一个 MACVLAN 网络

### 5.2 服务配置

1. 一个配置文件中服务可以填写多个，也可以不填写
2. 在使用 `mvconf up` 的时候会读取所有服务配置，并将服务所对应的容器一一连接到其所在的主机的 MACVLAN 上
3. 在使用 `mvconf disconnect` 和 `mvconf down` 时会读取服务名称和所关联网络，并尝试在每一台主机上将对应容器从主机上的该 MACVLAN 网络断开
4. 在使用 `mvconf uningress` 和 `mvconf reingress` 时会读取服务名称，并尝试在每一台主机上将对应容器从 ingress 网络断开（或连接）

#### 5.2.1 IP 池

服务在 `mvconf up` 时需要用到 `ip_pool` 配置

有两种配置写法

1. 单个 IP 如："192.168.2.100"
2. IP 段如："192.168.2.100-192.168.2.200"

在使用 `mvconf up` 时会尝试从 IP 池中依次取可用 IP 用于绑定容器。在有容器待绑定 但 IP 池耗尽时会报错并退出执行。

### 5.3 授权配置

可不填，具体见 [4. DCE 授权](#toc_8)


## 6. 命令

### 6.1 检查配置 (`mvconf config`)

> 使用方法：`mvconf [-f 配置文件] config`

会对检查到的错误报错

配置文件正确时会输出配置文件到标准输出

### 6.2 登陆 DCE (`mvconf login`)

> 使用方法：`mvconf login DCE控制器IP地址 -u 管理员账号 -p 管理员密码 `

如果不加 `-u` 或 `-p` 会要求在命令行输入账号或密码

更多参照 [4.1 使用 mvconf login 授权](#toc_7)

### 6.3 创建/连接 (`mvconf up`)

> 使用方法：`mvconf [-f 配置文件] up `

1. 根据配置尝试在每一台主机上创建配置中定义的 MACVLAN 网络
2. 根据配置将服务所对应的容器一一连接到其所在的主机的 MACVLAN 上

### 6.4 断开 MACVLAN (`mvconf disconnect`)

> 使用方法：`mvconf [-f 配置文件] disconnect `

根据配置文件尝试将服务的容器一一从对应主机上的对应 MACVLAN 网络断开

### 6.5 删除 MACVLAN 网络 (`mvconf rm`)

> 使用方法：`mvconf [-f 配置文件] rm `

根据配置文件尝试将 MACVLAN 从每个主机上删除

### 6.6 断开删除 (`mvconf down`)

> 使用方法：`mvconf [-f 配置文件] down `

相当于 `mvconf disconnect` + `mvconf rm`

### 6.7 断开 ingress 网络 (`mvconf uningress`)

> 使用方法：`mvconf [-f 配置文件] uningress `

根据配置文件尝试将服务的容器一一从 ingress 网络断开

### 6.8 连接 ingress 网络 (`mvconf reingress`)

> 使用方法：`mvconf [-f 配置文件] reingress `

根据配置文件尝试将服务的容器一一连接到 ingress 网络

### 6.9 MACVLAN 状态 (`mvconf status`)

> 使用方法：`mvconf [-f 配置文件] status [--sort 字段名列表] [--fields 字段名列表] --no-trunc`

1. 使用 `--no-trunc` 可以使输出不裁剪“容器 ID”等信息
2. 使用 `--sort macvlan_ip,service_name` 可以依次排序 `MACVLAN IP` 和 `SERVICE NAME` 字段。字段名称 'macvlan_ip' 等价于 'MACVLAN_IP' 等价于 'MACVLAN IP',字段间用逗号隔开
3. 使用 `--fields macvlan_ip,service_name` 可以只显示某些字段，字段同上

## 7. 开发

### 7.1 DEBUG 模式

将环境变量设置为 `DEBUG=1` 可以开启 debug 模式，该模式下会打出更多日志，方便排错。

### 7.2 构建 Linux 二进制文件

确保本机安装 Docker（Docker for mac/windows 也支持），在代码根目录执行 `make linux-bin` 即可在 `./bin` 下生成 mvconf 的 elf 可执行文件。


