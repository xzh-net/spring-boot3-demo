# 构建 MCP 服务端与客户端

MCP 是 Anthropic 公司推出的 "模型上下文协议"（Model Context Protocol），定义了大语言模型（LLM）与外部世界连接的开放标准，是构建在模型原生 tools（Function Calling）能力之上的一层编排与抽象层。

tools 只解决了 "让模型能输出函数名和参数" 这一个问题，MCP 解决的是：这些函数从哪来？（多个服务、动态安装），如何安全地调用？（权限、沙箱），如何传输大数据？（分块、流式），如何支持非函数类需求？（读取资源、获取提示模板）。

当模型 API 不支持原生的 tools 参数时，客户端会将工具描述拼接到系统提示词中作为降级方案。在目前生态中，由于并非所有模型都支持 function calling，这种拼接方式仍被广泛使用，是一种兼容性很强的落地手段。

工作流程

```mermaid
sequenceDiagram
    participant User as 用户
    participant Client as MCP客户端
    participant LLM as 大语言模型
    participant MCPServer as MCP服务器<br>(天气服务)

    Note over Client,MCPServer: 阶段1：连接与发现
    Client->>+MCPServer: 1. 建立连接 (stdio/HTTP)
    MCPServer-->>-Client: 2. 初始化握手，确认协议版本
    Client->>+MCPServer: 3. 请求可用工具列表 (tools/list)
    MCPServer-->>-Client: 4. 返回工具列表 (如 get_weather)

    Note over User,LLM: 阶段2：用户交互与意图理解
    User->>Client: 5. "大连今天天气怎么样？"
    Client->>+LLM: 6. 转发用户问题 + MCP工具定义
    LLM-->>-Client: 7. 返回结构化请求<br>(函数名: get_weather, 参数: city=大连)

    Note over Client,MCPServer: 阶段3：MCP调用与数据获取
    Client->>+MCPServer: 8. 请求调用工具 (tools/call)
    MCPServer-->>-Client: 9. 返回天气数据 (JSON格式)

    Note over Client,LLM: 阶段4：结果合成与最终回答
    Client->>+LLM: 10. 再次提问 + MCP工具返回结果
    LLM-->>-Client: 11. 生成最终自然语言回答
    Client->>User: 12. "大连今天多云转小雨，气温11℃到18℃..."
```

该项目实现了基于流式 HTTP（STREAMABLE）协议的 MCP 服务端，支持实时通知（资源、工具、提示词变更通知）。通过  `LoggingFilter` 过滤器，专门用于调试网关代理后的请求头参数异常情况，仅对 `/mcp/*` 路径生效。

客户端工具安装

```bash
npx @mcpjam/inspector@latest
```