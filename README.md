# Bitwarden Vault Manager

在浏览器中管理 Bitwarden 或 Vaultwarden 密码库。使用 API Key 登录，主密码用于在浏览器本地解密条目。登录页的「体验演示」可用示例数据试用，无需账号。[原项目在线演示](https://bitwarden.xuebz.com/)

## 密码库管理

- 按类型或文件夹浏览、搜索和编辑条目。支持批量移动、移入回收站、恢复和永久删除。
- 检查重复登录项并合并。用户名、密码或 TOTP 冲突、条目解密失败、含附件、属于组织或多个条目含通行密钥时，会跳过自动合并。
- 在「健康分析」中查看弱密码、空密码、重复使用的密码和 HTTP 地址。在「失效 URL」中手动开始检测，浏览器会连接登录条目对应的域名。

## 本地运行

使用 Node.js 20.19+（20.x）或 22.12 及以上版本。

```bash
npm ci
npm run dev
```

运行回归测试用 `npm test`，生成生产构建用 `npm run build`。测试使用模拟请求和示例凭证。

## 连接自托管密码库

在登录页选择「自托管 / Vaultwarden」，填写 Web Vault 根地址，例如 `https://vault.example.com/vault`。保留部署子路径，省略 `/api` 和 `/identity`。

本地开发和预览代理可连接本机或内网服务，请在可信网络中运行。服务器使用内部 CA 时，将 `NODE_EXTRA_CA_CERTS` 指向 CA 证书文件，再启动开发或预览服务。

## 部署到 Cloudflare Pages

官方 US 和 EU 服务可直接使用。要连接自托管服务，在 Pages 项目环境变量 `SELF_HOSTED_BASES` 中填写你信任的完整 HTTPS 根地址，包含端口和部署子路径。多个地址用英文逗号分隔。保存后重新部署：

```bash
npm run build
wrangler pages deploy dist --project-name bitwarden-vault-manager --branch main
```

## 加密登录文件

「加密登录」可导出 `.bwcred` 文件，其中含有 API 凭证、邮箱、服务器地址和主密码。请设置至少 12 个字符的独立文件口令。下次登录时选择「加密文件」，用该口令解锁。

旧版文件使用公开固定密钥，应按明文凭证保管。请用 API Key 登录后重新导出。

## 许可证

[MIT](LICENSE)
