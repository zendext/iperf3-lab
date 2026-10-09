# 网络协议指纹对照实验

基于上游 iperf3 3.22，commit `926bd905501b792bd082d2200d1d1a84aa543e3a`。
这是实验性 fork，用于比较相同服务器和端口上，原版协议与隐藏明文握手内容后的吞吐量。

## 使用

两端必须使用本分支编译的程序和**同一个密钥文件**。密钥只需在本机生成一次，
再通过 SSH/SCP 复制到服务端；不得提交密钥到 Git 或公开下载地址。

程序默认读取 `${XDG_CONFIG_HOME:-$HOME/.config}/iperf3-lab/wire.key`，
无需环境变量传密钥，也无需每次指定密钥参数。两端运行程序的用户各自持有同一份文件。
已有密钥时直接复制，不要重新生成两份不同的密钥。

```sh
umask 077
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/iperf3-lab"
openssl rand -hex 32 > "${XDG_CONFIG_HOME:-$HOME/.config}/iperf3-lab/wire.key"
```

预编译程序名是 `iperf3-lab`，支持 Linux x86_64，静态链接 musl 和 OpenSSL。
从源码本机编译时，以下示例中的 `./iperf3-lab` 替换为 `./src/iperf3`。

服务端：

```sh
./iperf3-lab -s -p 9876
```

客户端：

```sh
# 上传，单连接
./iperf3-lab -c SERVER_IP -p 9876 -t 30

# 下载，单连接
./iperf3-lab -c SERVER_IP -p 9876 -t 30 -R

# 下载，四连接（作为单独的一组对照）
./iperf3-lab -c SERVER_IP -p 9876 -t 30 -R -P 4

# UDP：目标速率自行调整，两端还需放行同一端口的 UDP
./iperf3-lab -c SERVER_IP -p 9876 -u -b 100M -t 30
```

默认启用实验协议。文件不存在或不是 64 个十六进制字符（可带 LF/CRLF 换行）时，
启动失败，不会静默降级。需要指定另一个文件时使用 `--wire-key-file /path/to/wire.key`；
该选项也供 systemd 服务读取 `LoadCredential` 提供的密钥文件。
旧的 `IPERF3_WIRE_KEY_FILE` 变量不再使用。

对照原版协议时，先结束实验服务端，然后两端均指定 `--wire-plain`：

```sh
# 服务端
./iperf3-lab --wire-plain -s -p 9876

# 客户端，必须保持目的 IP、端口、方向、时长、连接数一致
./iperf3-lab --wire-plain -c SERVER_IP -p 9876 -t 30 -R
```

原版模式可以与官方 iperf3 互通。默认端口仍是 5201；这里使用原测速命令的 9876。
对照时一次只改变一个变量，至少重复数次并交替测试顺序。

## 改动范围与限制

- 控制连接上的 cookie、状态字节、JSON 长度、测试参数、测试结果、错误和终止消息
  均用 OpenSSL AES-256-GCM 包装。
- TCP/SCTP 数据连接的 cookie 与拒绝消息使用同一包装；每次发送独立生成 nonce，
  所以同一会话的 cookie 在不同连接上的密文不同。
- UDP 建连请求和回复同样包装；接收端必须通过 GCM tag 验证后才使用明文。
- `--wire-plain` 保留原版协议。密钥在进程启动时加载一次，运行中更换文件需重启。
- 大量测速数据的收发保持上游实现，不加密、不填充。UDP 数据包里的时间戳和序号、
  数据块复用、连接结构、包长、持续发送行为和目的 IP/端口仍可被观察。
- 包装本身有固定结构：12 字节随机 nonce + 密文 + 16 字节 tag，且不填充长度。
  原来的 37 字节 cookie 变成 65 字节记录，1 字节状态变成 29 字节记录，
  UDP 建连消息变成 32 字节记录。后续仍可能对本变体建立新的指纹。
- 这是隐藏原版明文指纹的对照实验，不保证逃过 DPI，也不能据此直接认定运营商限速。
  它没有前向保密或防重放机制，不作为通用安全传输协议使用。
- 实验模式单条控制消息限制为 16 MiB；原版模式沿用上游限制。
- 预编译产物关闭 SCTP，仅支持 TCP/UDP。SCTP 源码路径已改，但未验证 SCTP 互通。
  库调用者需显式调用内部 `iperf_wire_init()`；本分支交付面向命令行程序。

## 从源码编译和验证

需要 C 编译工具、OpenSSL 开发包，以及运行回归检查用的 Python 3。

```sh
git clone --branch wire-obfuscation https://github.com/zendext/iperf3-lab.git
cd iperf3-lab
./configure --disable-shared --without-sctp --with-openssl=/usr
make -j4
make check
python3 tests/wire_regression.py
```

静态 Linux x86_64 产物使用官方 `alpine:3.22` 容器（musl）：

```sh
apk add --no-cache build-base openssl-dev openssl-libs-static linux-headers python3
./configure --enable-static-bin --without-sctp --with-openssl=/usr
make -j4
make check
python3 tests/wire_regression.py
strip src/iperf3
```

回归脚本在 loopback 上运行实际客户端和服务端，使用 TCP/UDP 转发代理记录网络字节，
不需要 root 权限或第三方 Python 包。覆盖 TCP 正向、反向、多连接、双向、分片接收，
UDP 正向、反向多连接、双向，原版模式，默认配置和显式密钥文件，
以及密钥错误、消息篡改和密钥文件错误。发送端和接收端都必须报告实际传输量。
检查原版 cookie、`client_version`、参数与统计字段未出现在记录的网络字节中，
并检查 UDP 建连消息已包装。它验证程序和上述字节特征，不验证运营商实际分类策略。

新增回归首次运行在未修改的 3.22 上，以 `client_version` 明文泄漏而失败；
修改后再运行应通过。上游 `make check` 为五项测试。
