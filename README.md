# proxy

一个使用 C++17 + CMake 编写的跨平台 HTTP/2 TLS 应用层隧道代理示例。

## 特性

- `server`：HTTP/2 TLS 服务端，使用 `nghttp2` 回调式处理 `/api/tunnel/*` 隧道 stream
- `client`：本地 SOCKS5 代理，通过 1 条长期 HTTP/2 TLS 连接复用多个 stream 转发
- Windows/Linux 统一使用 BoringSSL 提供 TLS 能力
- 唯一新增依赖为 `nghttp2 v1.68.1`
- 服务端证书运行时生成，不落盘
- 隧道传输使用 HTTP/2 stream：
  - `POST /api/tunnel/open`
  - `POST /api/tunnel/upload`
  - `GET /api/tunnel/events`
  - `POST /api/tunnel/close`
- 首页 `/` 返回普通 HTML 页面

## 构建

### Windows

构建时会通过 CMake `FetchContent` 直接从 GitHub 下载并编译 BoringSSL。

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

构建会直接编译仓库内置的 `third_party/nghttp2-1.68.1` 静态库。

默认固定拉取 GitHub 上已钉住的 BoringSSL 提交：

- `aa0acca1acf36b7fb16aa8a7b60b97d5cb01404d`

如果之后想跟进更新的上游版本，只需要改 `BORINGSSL_GIT_TAG`：

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBORINGSSL_GIT_TAG=<new_commit>
cmake --build build --config Release
```

### Linux

```bash
sudo apt-get install -y build-essential cmake
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## 运行

### 动态直连模式

```bash
./server --listen 8443
./client 127.0.0.1:8443 --listen 1080
```

### 上游 SOCKS5 代理模式

服务端把 `--target` 视为“下一跳 TCP 代理”，默认按 SOCKS5 协商，再让上游代理去连接真实目标：

```bash
./server --listen 8443 --target 127.0.0.1:1080
./client 127.0.0.1:8443 --listen 1080
```

### 固定原始转发模式

```bash
./server --listen 8443 --target 8.8.8.8:443 --target-type raw
./client 127.0.0.1:8443 --listen 1080
```

将浏览器或程序代理设置为 `SOCKS5 127.0.0.1:1080` 即可。

## 已知限制

- 当前仅支持 SOCKS5 `CONNECT`
- 传输层已经切换为“单条 HTTP/2 TLS 连接 + 多 stream 复用”
- `upload` 端点会把多个二进制帧批量打包到单次 `POST` 请求体中，`events` 端点负责长期返回下行帧
- 服务端 `--target` 默认按 SOCKS5 上游代理处理；若要回退到旧的“固定最终目标”模式，请使用 `--target-type raw`
- 客户端默认打印服务端证书指纹，不做正式 CA 校验
- Windows/Linux 服务端运行时证书统一为 BoringSSL 兼容 API 生成的 ECDSA P-384 自签名证书
- 未实现真正的后量子密钥交换、自定义 TLS 扩展或浏览器级 ClientHello 指纹伪装
- 首次配置需要联网访问 GitHub 以下载 BoringSSL 源码
