# OpenAI调用本地向量模型

EmbeddingModel接口提供两类方法

1. embed：仅获取向量
2. embedForResponse：包含元数据（Metadata），token使用情况和模型信息，需要监控、调试或计费的场景使用。