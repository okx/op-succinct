# Test Runner Setup Guide

## 解决 vk-map 下载问题

如果编译时遇到 `vk-map-v5.0.0` 下载失败，可以手动下载并设置环境变量。

### 方法 1: 使用环境变量（推荐）

```bash
# 1. 下载文件
curl -L https://sp1-circuits.s3.us-east-2.amazonaws.com/vk-map-v5.0.0 -o ~/vk_map.bin

# 2. 验证 SHA256（可选）
# 正确的 SHA256: 5e735f6e44f56e9eee91e5626252663afcc5263287d1c5980367b3f9f930a0e8
sha256sum ~/vk_map.bin

# 3. 设置环境变量
export VK_MAP_SRC_PATH=~/vk_map.bin

# 4. 编译
cd programs/test-runner
cargo build --release

# 或者一次性设置
VK_MAP_SRC_PATH=~/vk_map.bin cargo build --release
```

### 方法 2: 放到 sp1-prover 源码目录

```bash
# 1. 找到 sp1-prover 源码目录
SP1_PROVER_DIR=$(find ~/.cargo/registry -type d -name "sp1-prover-5.2.4" | head -1)

# 2. 下载文件到 src 目录
curl -L https://sp1-circuits.s3.us-east-2.amazonaws.com/vk-map-v5.0.0 -o "$SP1_PROVER_DIR/src/vk_map.bin"

# 3. 编译（不需要设置环境变量）
cd programs/test-runner
cargo build --release
```

### 文件信息

- **文件名**: `vk_map.bin`
- **SHA256**: `5e735f6e44f56e9eee91e5626252663afcc5263287d1c5980367b3f9f930a0e8`
- **URL**: `https://sp1-circuits.s3.us-east-2.amazonaws.com/vk-map-v5.0.0`
- **用途**: SP1 prover 需要的 verification key map 文件

### 验证下载

```bash
# 检查文件大小（应该约几 MB）
ls -lh ~/vk_map.bin

# 验证 SHA256
echo "5e735f6e44f56e9eee91e5626252663afcc5263287d1c5980367b3f9f930a0e8  ~/vk_map.bin" | sha256sum -c
```

