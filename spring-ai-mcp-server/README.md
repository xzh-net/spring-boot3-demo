# 基于 Spring AI 构建 MCP 服务端与客户端

实现了基于流式 HTTP（STREAMABLE）协议的 MCP 服务端，支持实时通知（资源、工具、提示词变更通知）。通过  `LoggingFilter` 过滤器，专门用于调试网关代理后的请求头参数异常情况，仅对 `/mcp/*` 路径生效。

客户端工具安装

```bash
npx @mcpjam/inspector@latest
```

