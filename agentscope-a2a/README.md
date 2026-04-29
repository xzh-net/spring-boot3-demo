# 基于 A2A 协议的分布式智能体构建

通过 **AgentScope Java SDK** 集成以及构建分布式 AI Agent 系统

## 获取服务

```
curl http://172.17.17.165:8888/.well-known/agent-card.json
```

## 服务调用


```txt
curl -X POST http://172.17.17.165:8888 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"message/stream","id":"1","params":{"message":{"role":"user","parts":[{"kind":"text","text":"生产环境巡检"}}]}}'
```

## AgentCard 获取的四种方式

- 直接构建

- 从 well-known 路径获取

- 从 Nacos 中发现

- 自定义解析器

