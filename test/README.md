# qtunnel Test Suite

统一的、模块化的测试框架。

## 文件结构

### 核心测试脚本

- **`test.sh`** - 主测试脚本（推荐使用）
  - 支持四种模式：`single`, `concurrent`, `large-file`, `all`
  - 使用共享的测试函数库
  - 自动处理证书生成、编译、启动和清理

- **`test_common.sh`** - 共享的测试函数库
  - 日志函数：`info()`, `error()`, `warn()`, `debug()`
  - 设置函数：`setup_paths()`, `generate_certs()`, `build_project()`
  - 启动函数：`start_server()`, `start_client()`, `cleanup_all()`
  - 测试函数：`health_check()`, `test_single_request()`, `test_concurrent_requests()`, `test_large_file_concurrent()`

### 专用测试脚本

- **`test_local_dns.sh`** - 本地环回测试（不需要外网）
  - 专门测试本地 DNS 功能
  - 不依赖外部 URL

- **`diagnose.sh`** - 诊断脚本
  - 检查 DNS 异步实现
  - 验证单元测试

- **`run_test.sh`** - 完整的测试套件（兼容遗留脚本）
  - 包含详细的日志记录和结果保存

## 使用方法

### 运行单个请求测试
```bash
./test.sh single
```
- 启动服务器和客户端
- 执行单个 HTTPS 请求
- 验证基本连接功能

### 运行并发请求测试
```bash
./test.sh concurrent
```
- 启动服务器和客户端
- 并发执行 20 个 HTTPS 请求
- 验证并发处理能力

### 运行大文件 + 并发测试
```bash
./test.sh large-file
```
- 启动服务器和客户端
- 同时下载大文件 (10MB) 和执行 20 个并发请求
- 验证多任务处理能力

### 运行所有测试
```bash
./test.sh all
# 或
./test.sh
```
- 顺序运行以上三个测试
- 每个测试之间自动清理进程

### 查看帮助
```bash
./test.sh help
```

## 输出

测试结果保存在 `results/` 目录：
- 时间戳：`result_YYYYMMDD_HHMMSS_[mode].txt`
- 包含测试状态、服务器日志、客户端日志

日志保存在 `logs/` 目录：
- `server.log` - 服务器日志
- `client.log` - 客户端日志
- `bigfile.bin` - 大文件下载（大文件测试时）

## 本地 DNS 测试

对于专门的本地 DNS 功能测试：
```bash
./test_local_dns.sh
```
- 不需要外网连接
- 使用本地环回地址

## 诊断

检查编译和单元测试：
```bash
./diagnose.sh
```
- 验证 DNS resolver 实现
- 运行 DNS 单元测试

## 配置

默认配置（可在脚本中修改）：
- 服务器端口：18443
- SOCKS5 监听端口：11080
- 证书目录：`certs/`
- 日志目录：`logs/`
- 结果目录：`results/`

## 常见问题

### 测试超时
- 增加 `curl` 的超时时间（默认 15 秒）
- 检查网络连接和 DNS 解析

### 证书错误
- 删除 `certs/` 目录让脚本重新生成
- 或手动运行 `generate_certs()` 函数

### 端口被占用
- 修改 `SERVER_PORT` 和 `SOCKS_PORT` 变量
- 或使用 `netstat` 检查占用的进程

### 权限不足
- 确保脚本有执行权限：`chmod +x test.sh`
- 对于 OpenSSL：需要 write 权限到 `certs/` 目录
