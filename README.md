# claw_key_safe

在 OpenClaw 的消息输出层对常见 API key / token / secret 做文本脱敏，只影响**用户可见消息**，不会修改运行时真实密钥值。

## 特性

- 只修改 `normalizeReplyPayload()` 产出的用户可见回复
- 同时处理 `payload.text` 和 `payload.channelData`
- 优先脱敏环境变量和配置文件里的显式密钥
- 再用正则兜底处理常见密钥格式
- 支持自定义替换文案
- 不包含任何真实凭证、示例仓库内无隐私信息

## 当前覆盖

- 显式键名：`apiKey`、`apiToken`、`appSecret`、`clientSecret`、`accessToken`、`refreshToken`、`authToken`、`gatewayToken`、`webhookSecret`、`signingSecret`、`privateKey`、`licenseKey`、`token`、`secret`、`password`
- 常见前缀：`sk-` / `sk_`、`rk-` / `rk_`、`pk-` / `pk_`、`pat-` / `pat_`
- GitHub：`ghp_`、`gho_`、`ghu_`、`ghs_`、`ghr_`
- GitLab：`glpat-`
- Slack：`xoxa-`、`xoxb-`、`xoxp-`、`xoxr-`、`xoxs-`
- Google：`AIza...`、`ya29....`
- AWS：`AKIA...`、`ASIA...`
- JWT 三段式 token
- `Bearer xxx` 这类 Authorization 字符串

## 文件

- `patch-openclaw-output-redaction.py`: 对 OpenClaw `reply-*.js` bundle 打补丁

## 用法

### 1. 在自定义镜像里复制并执行补丁

```dockerfile
FROM ghcr.io/openclaw/openclaw:latest

USER root

COPY patch-openclaw-output-redaction.py /usr/local/bin/patch-openclaw-output-redaction.py

RUN python3 /usr/local/bin/patch-openclaw-output-redaction.py
```

如果你的基础镜像里没有 `python3`，先安装：

```dockerfile
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
```

### 2. 可选环境变量

```dockerfile
ENV CLAW_KEY_SAFE_REPLACEMENT="KFC-Crazy-Thursday-VME50"
ENV CLAW_KEY_SAFE_CONFIG_PATH="/home/node/.openclaw/openclaw.json"
ENV CLAW_KEY_SAFE_DIST_DIR="/app/dist"
```

- `CLAW_KEY_SAFE_REPLACEMENT`: 用户看到的替换文本，默认 `***REDACTED***`
- `CLAW_KEY_SAFE_CONFIG_PATH`: OpenClaw 配置文件路径，用于收集显式密钥
- `CLAW_KEY_SAFE_DIST_DIR`: OpenClaw 构建产物目录，默认 `/app/dist`

### 3. Docker Compose 示例

```yaml
services:
  openclaw-gateway:
    build:
      context: .
      dockerfile: Dockerfile.openclaw-safe
    environment:
      CLAW_KEY_SAFE_REPLACEMENT: KFC-Crazy-Thursday-VME50
```

## 工作原理

补丁会把一段脱敏逻辑注入到 OpenClaw 的 `normalizeReplyPayload()` 附近，并在回复即将返回前执行：

1. 从环境变量中提取可能的显式密钥
2. 从配置文件中提取常见键名下的密钥
3. 对 `text` 和 `channelData` 中的字符串做替换
4. 跳过明显是 URL / 图片 / 文件路径的字段，减少误伤

## 验证方法

构建并启动后，可以用以下内容做验证：

```text
sk_9x2y7z4a1b6c8d3e5f0g7h2j9k4l6m8n0p2q5r7s1t3v8w9
ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD
Bearer abcdefghijklmnopqrstuvwxyz123456
```

如果补丁生效，用户最终看到的应是你设置的替换文本，而不是原始字符串。

## 兼容性说明

- 该补丁依赖 OpenClaw 当前 `reply-*.js` bundle 中 `normalizeReplyPayload()` 的结构
- 如果 OpenClaw 上游改动了编译产物结构，锚点可能需要同步调整
- 建议升级 OpenClaw 后重新验证一次补丁是否仍能命中

## 隐私说明

- 本仓库不包含任何真实 API key、token、secret、应用配置
- README 中所有示例字符串均为占位示例
- 发布前请不要提交你自己的 `openclaw.json`、`.env`、会话日志或容器导出文件

## License

MIT
