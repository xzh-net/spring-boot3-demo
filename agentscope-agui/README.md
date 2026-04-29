# AG-UI 多智能体服务

本项目是一个基于 Spring Boot 4.0.4 和 AgentScope 1.0.11 的智能体服务应用，实现了 AG-UI 协议 的前后端集成。项目展示了如何将 AgentScope 智能体通过 AG-UI 协议暴露给客户端，支持流式通信和多智能体路由。

## 启动应用

```bash
mvn spring-boot:run
```

## 访问地址

```
http://172.17.17.165:8080
```

## API 调用


```txt
curl -N -X POST http://172.17.17.165:8080/agui/run \
    -H "Content-Type: application/json" \
    -d '{"threadId":"test","runId":"1","messages":[{"id":"m1","role":"user","content":"Hello!"}]}'
```

## 指定智能体

```
# 方式1：URL 路径
curl -X POST http://172.17.17.165:8080/agui/run/default \
  -H "Content-Type: application/json" \
  -d '{"threadId":"test","runId":"1","messages":[{"id":"m1","role":"user","content":"大连天气怎么样"}]}'

# 方式2：请求头
curl -X POST http://172.17.17.165:8080/agui/run \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: chat" \
  -d '{"threadId":"test","runId":"1","messages":[{"id":"m1","role":"user","content":"大连天气怎么样"}]}'
```

