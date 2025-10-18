# Spring AI 集成 OpenAI 实现对话问答的两种方式

## 一、设计层级不同
| 文件                   | 层级             | 说明                                                         |
| ---------------------- | ---------------- | ------------------------------------------------------------ |
| `ChatClientController` | **高层封装**     | 使用 `ChatClient`，提供了更高级的、链式调用的API，内置了记忆（Memory）、日志（Logger）等Advisor机制。 |
| `ChatModelController`  | **底层直接调用** | 直接使用 `ChatModel`，更接近原始模型调用，需要手动构建 `Prompt` 和解析 `ChatResponse`。 |

## 二、功能封装差异

| 功能         | `ChatClientController`      | `ChatModelController`   |
| ------------ | --------------------------------- | ----------------------------- |
| **记忆功能** | ✅ 内置 `MessageChatMemoryAdvisor` | ❌ 需手动实现                  |
| **日志记录** | ✅ 内置 `SimpleLoggerAdvisor`      | ❌ 需手动实现                  |
| **流式响应** | ✅ 支持SSE（Server-Sent Events）   | ✅ 支持Flux流式输出            |
| **JSON模式** | ❌ 未展示                          | ✅ 支持JSON Schema响应格式     |
| **选项配置** | 通过 `ChatOptions` 设置     | 通过 `ChatOptions` 设置 |

## 三、代码风格与使用方式

| 方面           | `ChatClientController`       | `ChatModelController`                |
| -------------- | ---------------------------------- | ------------------------------------------ |
| **代码简洁性** | 更简洁，链式调用                   | 更底层，需手动处理响应                     |
| **灵活性**     | 较高，适合快速集成                 | 更高，适合定制化场景                       |
| **适用场景**   | 快速开发、集成功能（如记忆、日志） | 需要直接控制模型调用、自定义响应处理的场景 |

## 四、方法对比

| 方法类型       | `ChatClientController` | `ChatModelController`            |
| -------------- | ---------------------------- | -------------------------------------- |
| **简单调用**   | `simpleChat()`               | `simpleChat()`                         |
| **流式调用**   | `streamChat()`               | `streamChat()`                         |
| **自定义选项** | 在构造时统一设置             | 每个请求可独立设置 `ChatOptions` |
| **JSON模式**   | 未实现                       | `jsonChat()` 支持JSON Schema           |


## 五、总结

- 如果你希望**快速集成**聊天功能，并自带记忆、日志等增强功能，使用 **`ChatClientController`**。
- 如果你需要**更底层的控制**，比如自定义每个请求的选项、处理原始响应，或者使用JSON模式等，使用 **`ChatModelController`**。