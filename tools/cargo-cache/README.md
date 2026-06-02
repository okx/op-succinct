# cargo-cache

预打包的 cargo git 依赖缓存，给**无法访问 `gitlab.okg.com`** 的测试机用。

## 文件

- `ok-kms-rust-cache.tar.xz` — `ok-kms-rust@dda1c2b2` (v1.0.0) 的 cargo git db + checkouts，hash `9fb8a069048fd415`
- `install-ok-kms-rust.sh` — 一键解压到本机 cargo home

## 测试机用法

```bash
git clone <op-succinct repo> /tmp/op-succinct
cd /tmp/op-succinct/tools/cargo-cache
./install-ok-kms-rust.sh
# 默认 CARGO_HOME=$HOME/.cargo，root 用户会落到 /root/.cargo
# 如果你的 cargo home 不在标准位置：
#   CARGO_HOME=/custom/path ./install-ok-kms-rust.sh
```

装完直接回 x2 工作区跑 `cargo build`，不再尝试连 gitlab.okg.com。

## 何时需要更新

`ok-kms-rust` 依赖版本变化时（x2 Cargo.toml 改了它的 tag / rev）。重新打：

```bash
# 在能访问 gitlab.okg.com 的机器上，先 cargo build x2 让 cargo fetch 新版本
cd ~/.cargo/git
tar cJf /path/to/op-succinct/tools/cargo-cache/ok-kms-rust-cache.tar.xz \
    db/ok-kms-rust-9fb8a069048fd415 \
    checkouts/ok-kms-rust-9fb8a069048fd415
```

如果新版本的 git URL 变了，hash（`9fb8a069048fd415` 那部分）会变，需要同步改 `install-ok-kms-rust.sh` 里的 `DB_DIR` / `CK_DIR` 路径。

## 安全

- 这个 tarball 含 `ok-kms-rust` 私有源码
- **只允许 push 到 origin（gitlab.okg.com，内网）**
- 严禁 push 到 upstream（succinctlabs/op-succinct 公开 github）
