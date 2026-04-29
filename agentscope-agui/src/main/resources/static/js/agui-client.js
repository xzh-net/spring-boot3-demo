/*
 * Copyright 2024-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * AG-UI Protocol Client
 * 符合 AG-UI 标准协议的客户端库，支持 SSE 流式事件处理、运行中止等功能。
 *
 * @example
 * const client = new AguiClient('/agui/run');
 * await client.run({
 *     threadId: 'thread-123',
 *     runId: 'run-456',
 *     messages: [{ id: 'msg-1', role: 'user', content: 'Hello!' }]
 * }, {
 *     onTextContent: (delta) => console.log(delta),
 *     onReasoningContent: (delta) => console.log('Reasoning:', delta),
 *     onRunFinished: () => console.log('Done')
 * });
 */
class AguiClient {
    /**
     * 创建一个 AG-UI 客户端实例
     * @param {string} endpoint - AG-UI 服务的 /run 端点 URL
     */
    constructor(endpoint) {
        this.endpoint = endpoint;
        this.abortController = null;
    }

    /**
     * 中止当前正在进行的运行（如果存在）
     * 会关闭 SSE 连接，后端应相应停止生成并清理资源
     */
    abort() {
        if (this.abortController) {
            console.log('[AguiClient] Aborting current run...');
            this.abortController.abort();
            this.abortController = null;
        }
    }

    /**
     * 检查当前是否有正在进行的运行
     * @returns {boolean} 正在运行返回 true，否则返回 false
     */
    isRunning() {
        return this.abortController !== null;
    }

    /**
     * 启动智能体运行，通过 SSE 接收流式事件
     * @param {Object} input - 运行输入参数
     * @param {string} input.threadId - 会话线程 ID
     * @param {string} input.runId - 本次运行唯一 ID
     * @param {Array} input.messages - 消息历史数组，每条包含 id, role, content
     * @param {Array} [input.tools] - 可选工具列表
     * @param {Array} [input.context] - 可选上下文信息
     * @param {Object} [input.state] - 可选状态数据
     * @param {Object} [input.forwardedProps] - 可选转发属性
     * @param {Object} callbacks - 事件回调函数集合
     * @param {Function} [callbacks.onRunStarted] - 运行开始时触发
     * @param {Function} [callbacks.onRunFinished] - 运行结束时触发
     * @param {Function} [callbacks.onTextMessageStart] - 文本消息开始时触发
     * @param {Function} [callbacks.onTextContent] - 收到文本内容增量时触发
     * @param {Function} [callbacks.onTextMessageEnd] - 文本消息结束时触发
     * @param {Function} [callbacks.onReasoningMessageStart] - 推理消息开始时触发
     * @param {Function} [callbacks.onReasoningContent] - 收到推理内容增量时触发
     * @param {Function} [callbacks.onReasoningMessageEnd] - 推理消息结束时触发
     * @param {Function} [callbacks.onToolCallStart] - 工具调用开始时触发
     * @param {Function} [callbacks.onToolCallArgs] - 收到工具参数增量时触发
     * @param {Function} [callbacks.onToolCallEnd] - 工具调用结束时触发
     * @param {Function} [callbacks.onStateSnapshot] - 收到状态快照时触发
     * @param {Function} [callbacks.onStateDelta] - 收到状态增量时触发
     * @param {Function} [callbacks.onError] - 发生错误时触发
     * @returns {Promise<void>} 运行结束后 resolve
     * @throws {Error} 当 HTTP 请求失败时抛出
     */
    async run(input, callbacks = {}) {
        this.abortController = new AbortController();
        const signal = this.abortController.signal;

        let response;
        try {
            response = await fetch(this.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'text/event-stream'
                },
                body: JSON.stringify(input),
                signal: signal
            });
        } catch (err) {
            this.abortController = null;
            throw err;
        }

        if (!response.ok) {
            this.abortController = null;
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) {
                    break;
                }
                buffer += decoder.decode(value, { stream: true });

                // SSE 消息分隔符：优先尝试 \n\n，其次 \r\n\r\n
                let delimiter = '\n\n';
                let delimiterIndex = buffer.indexOf(delimiter);
                if (delimiterIndex === -1) {
                    delimiter = '\r\n\r\n';
                    delimiterIndex = buffer.indexOf(delimiter);
                }

                while (delimiterIndex !== -1) {
                    const message = buffer.substring(0, delimiterIndex);
                    buffer = buffer.substring(delimiterIndex + delimiter.length);
                    this._processSseMessage(message, callbacks);

                    // 继续寻找下一条消息
                    delimiterIndex = buffer.indexOf('\n\n');
                    if (delimiterIndex === -1) {
                        delimiterIndex = buffer.indexOf('\r\n\r\n');
                        if (delimiterIndex !== -1) delimiter = '\r\n\r\n';
                    } else {
                        delimiter = '\n\n';
                    }
                }
            }
            // 处理缓冲区残留数据
            if (buffer.trim()) {
                this._processSseMessage(buffer, callbacks);
            }
        } finally {
            reader.releaseLock();
            this.abortController = null;
        }
    }

    /**
     * 处理单条 SSE 原始消息（可能包含多行 data: 行）
     * @param {string} messageText - SSE 消息文本
     * @param {Object} callbacks - 事件回调
     * @private
     */
    _processSseMessage(messageText, callbacks) {
        const lines = messageText.split(/\r?\n/);
        for (const line of lines) {
            if (line.startsWith('data:')) {
                try {
                    // 兼容 "data: " 和 "data:" 两种格式
                    const jsonStr = line.startsWith('data: ') ? line.substring(6) : line.substring(5);
                    const event = JSON.parse(jsonStr);
                    this._handleEvent(event, callbacks);
                } catch (e) {
                    console.warn('[AguiClient] Failed to parse event:', line, e);
                }
            }
        }
    }

    /**
     * 处理单个 AG-UI 事件对象，根据事件类型调用对应的回调
     * @param {Object} event - 事件对象，必须包含 type 字段
     * @param {Object} callbacks - 事件回调集合
     * @private
     */
    _handleEvent(event, callbacks) {
        if (!event || !event.type) {
            console.warn('[AguiClient] Invalid event received:', event);
            return;
        }

        const type = event.type;
        try {
            switch (type) {
                case 'RUN_STARTED':
                    callbacks.onRunStarted?.(event.threadId, event.runId);
                    break;
                case 'RUN_FINISHED':
                    callbacks.onRunFinished?.(event.threadId, event.runId);
                    break;
                case 'TEXT_MESSAGE_START':
                    callbacks.onTextMessageStart?.(event.messageId, event.role);
                    break;
                case 'TEXT_MESSAGE_CONTENT':
                    if (event.delta) {
                        callbacks.onTextContent?.(event.delta, event.messageId);
                    }
                    break;
                case 'TEXT_MESSAGE_END':
                    callbacks.onTextMessageEnd?.(event.messageId);
                    break;
                case 'REASONING_MESSAGE_START':
                    callbacks.onReasoningMessageStart?.(event.messageId, event.role);
                    break;
                case 'REASONING_MESSAGE_CONTENT':
                    if (event.delta) {
                        callbacks.onReasoningContent?.(event.delta, event.messageId);
                    }
                    break;
                case 'REASONING_MESSAGE_END':
                    callbacks.onReasoningMessageEnd?.(event.messageId);
                    break;
                case 'TOOL_CALL_START':
                    callbacks.onToolCallStart?.(event.toolCallId, event.toolCallName);
                    break;
                case 'TOOL_CALL_ARGS':
                    if (event.delta) {
                        callbacks.onToolCallArgs?.(event.toolCallId, event.delta);
                    }
                    break;
                case 'TOOL_CALL_END':
                    callbacks.onToolCallEnd?.(event.toolCallId);
                    break;
                case 'STATE_SNAPSHOT':
                    callbacks.onStateSnapshot?.(event.snapshot);
                    break;
                case 'STATE_DELTA':
                    callbacks.onStateDelta?.(event.delta);
                    break;
                case 'RAW':
                    if (event.rawEvent?.error) {
                        callbacks.onError?.(event.rawEvent.error);
                    } else {
                        callbacks.onRawEvent?.(event.rawEvent);
                    }
                    break;
                default:
                    console.log('[AguiClient] Unknown event type:', type, event);
            }
        } catch (err) {
            console.error('[AguiClient] Error handling event:', type, err);
        }
    }
}

// 支持 CommonJS 和全局暴露
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AguiClient };
} else {
    window.AguiClient = AguiClient;
}