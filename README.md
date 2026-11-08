# 电视代理（SetTVProxy）

Android TV 一键式网络代理工具。首页只保留一个「开启 / 关闭」大按钮和一个「设置」按钮，
全部配置集中在设置页；一键开关**确认成功后应用立即退出前台**，回到桌面，不占用遥控器焦点。
界面为深色大字号，完全适配遥控器方向键（D-pad）。

## 两种工作模式

| 模式 | 原理 | 覆盖范围 | 是否需要授权 |
|---|---|---|---|
| **系统代理** | 写 `Settings.Global.http_proxy` | 仅主动遵循系统代理的 App 的 HTTP/HTTPS(TCP) | 需 adb 授予 `WRITE_SECURE_SETTINGS` |
| **VPN 全局** | `VpnService` 建 TUN 捕获流量，转发到 SOCKS5 / HTTP CONNECT 代理 | 所有 App 的 TCP + DNS + UDP | 首次需确认系统 VPN 连接对话框 |

VPN 全局模式是让 YouTube 等使用 QUIC/UDP 的视频应用也能走代理的关键。开启「域名透传」后，
DNS 由本地 fake-IP 代答，代理端拿到的是**域名**而不是墙内侧解析出的 IP，按域名分流与远程 DNS 才能生效。

## 功能

- 一键开启 / 关闭；成功执行后自动退出前台，失败则留在页面显示原因。
- 首页仅显示当前状态与两个按钮；设置页集中管理：代理主机 / 端口 / DNS / 工作模式 / 代理协议 /
  认证账号密码 / 域名透传 / UDP 策略 / 应用过滤。
- **fake-IP + 域名透传（默认开启）**：本地伪造 DNS A 记录（`198.18.0.0/16`），AAAA / HTTPS 返回 NODATA
  强制走 IPv4；TCP 与 UDP 请求用 SOCKS5 `ATYP=DOMAIN` 或 HTTP CONNECT 域名形式发给代理，由代理端远程解析。
- 协议支持：HTTP CONNECT（含 Basic 认证）、SOCKS5（无认证 / 用户名密码认证 RFC 1929）。
- UDP 策略：**SOCKS5 UDP ASSOCIATE 转发（默认，QUIC 不再被硬丢）**；可切回「丢弃」强制 QUIC 回退 TCP。
  HTTP 模式下自动退回丢弃。
- 应用过滤：全部应用（默认不过滤）/ 排除选中走直连 / 仅允许选中走代理。
  **是否走代理、怎么分流由代理服务器的规则决定**，App 默认不干预。
- 正式 PNG 启动图标（mdpi ~ xxxhdpi 五档）与 Android TV 横幅（`320x180`）。
- 系统代理模式默认例外列表：`localhost`、`127.0.0.1`；配置持久化，重启后保留。

## 目录结构

```
settvproxy/
├── build.gradle
├── settings.gradle
└── app/
    ├── build.gradle
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/example/settvproxy/
        │   ├── MainActivity.java          # 首页：一键开关、VPN 授权、成功后自动退出
        │   ├── SettingsActivity.java      # 统一设置页
        │   ├── AppPickerActivity.java     # 应用过滤列表与过滤模式
        │   ├── ProxyManager.java          # 系统全局代理（主/备方案）
        │   ├── ProxyVpnService.java       # VpnService、物理网络绑定、认证、握手、应用过滤
        │   ├── Prefs.java                 # 配置持久化
        │   └── vpn/
        │       ├── FakeDns.java           # fake-IP 池、DNS 应答构造、域名映射
        │       ├── Packets.java           # IPv4/TCP/UDP 解析、构造、校验和、SOCKS5 UDP 封装
        │       ├── TcpConnection.java     # TCP 会话状态机与双向转发
        │       ├── UdpRelay.java          # SOCKS5 UDP ASSOCIATE 中继
        │       └── TunLoop.java           # TUN 读写、会话分发、fake DNS 代答
        └── res/                           # 布局、字符串、主题、mipmap 图标、TV banner
```

## 构建

使用 Android Studio 打开本目录，或命令行：

```bash
./gradlew assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

> 不依赖任何第三方库，仅使用 Android 框架（AGP 8.7.3 / compileSdk 35 / minSdk 21 / targetSdk 33）。
> Java 编译编码已固定为 UTF-8（源码含中文注释）。命令行构建需要能定位 Android SDK
> （`ANDROID_HOME` 环境变量或项目根目录的 `local.properties`）。

## 安装到电视

```bash
adb connect <电视IP>:5555
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## 授权说明

### VPN 全局模式（无需 root，推荐）
首次点「开启代理」会弹出系统 VPN 连接确认框，用遥控器确认即可。

### 系统代理模式
需在电脑上一次性授权：

```bash
adb shell pm grant com.example.settvproxy android.permission.WRITE_SECURE_SETTINGS
```

未授权时应用会提示该命令，并自动尝试 WiFi 反射方案（部分旧设备 / root 设备有效）。

## 使用说明

1. 首次进入点「设置」，填写代理主机 / IP 与端口，选择工作模式（推荐 **VPN 全局**）与协议
   （推荐 **SOCKS5**，域名透传与 UDP 转发支持更完整），然后返回首页。
2. 首页点「开启代理」；首次需确认系统 VPN 连接。状态变为「代理已开启」后应用自动退回桌面。
3. 再次进入应用，点「关闭代理」即停止并自动退出。
4. 设置页其它项：
   - **DNS**：仅在关闭「域名透传」时作为直连上游使用，只支持 IPv4 地址。
   - **代理账号 / 密码**：HTTP Basic 与 SOCKS5 用户名密码认证共用，留空即无认证。
   - **域名透传**：点击在「开启（fake-IP 远程解析）」与「关闭（本地直连 DNS）」间切换。
   - **UDP 策略**：默认「SOCKS5 UDP 转发」，QUIC 走 UDP 不再被丢弃；可切回「丢弃」强制回退 TCP。
     仅 SOCKS5 模式生效，HTTP 模式自动退回丢弃。
   - **应用过滤**：默认不过滤，分流交给代理端；需要时再打开应用选择页配置。
5. 修改任何配置后需**重新开启代理**才会生效。

## 实现细节

### fake-IP + 域名透传

默认开启，是解决海外域名在墙内侧被解析、IPv6 黑洞、代理端无法按域名分流的关键：

- `VpnService.Builder.addDnsServer("198.18.0.1")`，`TunLoop` 拦截所有 UDP 53 查询，由 `FakeDns` 本地代答，
  不访问任何上游 DNS；
- A 查询返回 `198.18.0.0/16` 网段虚拟 IP（TTL 60s）并记录「虚拟 IP → 域名」，
  AAAA / HTTPS / 其它类型返回 NOERROR + NODATA，客户端因此只用 IPv4；
- TCP SYN 与 UDP 包用 `FakeDns.lookup()` 还原域名：
  - SOCKS5 CONNECT → `ATYP=0x03` DOMAIN；
  - HTTP CONNECT → `CONNECT domain:port`；
  - SOCKS5 UDP 请求 → `ATYP=DOMAIN`，回包为域名形式时用会话最近一次的目标地址还原源 IP/端口；
- 映射丢失（服务重启或地址池耗尽回收）时对 TCP 回 RST、对 UDP 丢弃，促使应用重新解析；
- 关闭该开关后回退到旧行为：DNS 直连填写的上游，SOCKS5 使用 `ATYP=IPv4`。

### 认证

- SOCKS5：声明支持 `NO-AUTH` 与 `USERNAME/PASSWORD`（RFC 1929），按服务端选择的方法执行；
  配置了账号时优先提供两种方法，服务端选无认证也接受。
- HTTP CONNECT：配置了账号时附加 `Proxy-Authorization: Basic <base64>`。
- `ProxyVpnService.socks5Negotiate()` 被 TCP CONNECT 与 UDP ASSOCIATE 共用。

### 防止「代理连代理」自环

某些常驻 App 会缓存旧的 HTTP 代理设置，周期性连接 `代理服务器IP:端口`。这些包进入 TUN 后，
若当成普通连接再去做一次 SOCKS5 / HTTP 握手，就会不断派生「通过代理连代理」的无效连接，
拖慢所有请求。处理方式：

- 在 `establish()` **之前**找到一个具备 INTERNET 能力且不是 VPN 的物理网络（通常是 WiFi）；
- 所有到代理的 TCP socket 用 `Network.getSocketFactory().createSocket()` 创建，
  UDP / DNS socket 用 `Network.bindSocket()` 绑定，连接天然不经过 `tun0`，不再依赖
  `VpnService.protect()` 是否返回 true；找不到物理网络时才回退到 `protect()`；
- `TunLoop` 丢弃目标为代理端点的 UDP 包；
- `ProxyVpnService.openTunnel()` 识别目标为代理端点的 TCP 连接时，返回一条直接连到代理端口的裸
  Socket，字节原样转发，不做二次握手。

### UDP 转发（默认开启，仅 SOCKS5 模式）

每个本地 UDP 端点建立一条独立关联（一条 UDP ASSOCIATE 控制连接 + 一个绑定到物理网络的
DatagramSocket）。SOCKS5 UDP 中继没有多路复用标识，独立关联保证回包能准确映射回原始本地端口。
控制连接关闭即代表中继失效；会话 60 秒无活动自动回收。

- 请求的 `DST.ADDR` 用 `0.0.0.0`，由服务端按实际来源判定；
- 数据封装为 `RSV(2) FRAG(0) ATYP=(IPv4 或 DOMAIN) ADDR PORT(2) DATA`；
- 分片包（FRAG≠0）、IPv6 回包不支持，直接丢弃；
- UDP 53 由本地 fake DNS 代答，不走中继；
- 代理端需开启 UDP ASSOCIATE（SOCKS5 握手返回 `REP=0` 即支持），否则应切回「丢弃 UDP」。

### 应用过滤

`VpnService.Builder.addAllowedApplication()` 与 `addDisallowedApplication()` 互斥，实现中按模式二选一：
白名单模式下只调 `addAllowedApplication`，此时应用自身不在名单里即自动直连；
其余模式调 `addDisallowedApplication`（含自身包名）。应用列表来自 LAUNCHER / LEANBACK_LAUNCHER 查询，
Manifest 中已声明 `<queries>` 以满足 Android 11+ 包可见性限制。默认不过滤，分流规则由代理端决定。

## 已知边界

VPN 模式是**纯 Java 实现的轻量 TCP/UDP-over-TUN 桥**，生产环境若有更高性能或完整性要求，
建议把 `vpn/` 层替换为 `hev-socks5-tunnel`、`tun2socks` 等原生实现：

- 仅 IPv4；IPv6 流量被收进 TUN 后丢弃（fake DNS 也会让客户端拿不到 AAAA）。
- 域名透传依赖代理端支持远程 DNS（SOCKS5 `ATYP=DOMAIN` / HTTP CONNECT 域名形式）。
- 若设备开启了「私人 DNS（DNS-over-TLS）」，系统 DNS 可能绕过 VPN 的 DNS 服务器，
  导致 fake-IP 不生效；此时应关闭私人 DNS，或在设置页关闭「域名透传」回退到直连上游 DNS。
- 本地代答 TCP，不实现重传与拥塞控制；丢包依赖对端重传，弱网下可能略降速。
- UDP 中继不支持分片与 IPv6 回包；部分代理服务端未开启 UDP ASSOCIATE 时会失败，
  此时应切回「丢弃 UDP」策略。
- 代理主机若填域名，会在建立 VPN **之前**解析并缓存为 IP，避免 DNS 死循环。

## 验证是否生效

```bash
adb shell settings get global http_proxy        # 系统代理模式
adb shell dumpsys connectivity | grep -i vpn    # VPN 模式
adb logcat -d -s TunLoop ProxyVpnService UdpRelay
aapt2 dump badging app-debug.apk | grep application-icon   # 图标资源
```

- `physical network=... udpRelay=true domainPassthrough=true` 表示 UDP 转发已启用且 socket 绑定物理网络；
- `fake dns answer ...B` 表示 DNS 已由本地 fake-IP 代答，没有走墙内侧上游；
- `tunnel DOMAIN www.youtube.com:443` 表示域名已透传给代理（若为 `tunnel IP ...` 则仍是 IP 形式）；
- `proxy endpoint direct passthrough` 表示缓存了旧代理设置的 App 已被直连透传；
- `tunnel IP <代理服务器地址>:<端口>` 应为 0 次，出现即说明仍有自环；
- `protect failed, proxy connection may loop` 不应再出现。

## 自定义

- 替换 `res/mipmap-*/ic_launcher.png`（48/72/96/144/192px）与 `res/drawable-xhdpi/banner.png`（320x180）。
- 例外域名（系统代理模式）在 `ProxyManager.EXCLUSIONS` 中补充。
- 需要完整 UDP 分片支持，可扩展 `UdpRelay` 与 `Packets.parseSocksUdpReply()`。
