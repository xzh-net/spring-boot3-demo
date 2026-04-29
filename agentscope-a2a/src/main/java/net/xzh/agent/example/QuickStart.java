package net.xzh.agent.example;

import io.agentscope.core.ReActAgent;
import io.agentscope.core.formatter.openai.OpenAIMultiAgentFormatter;
import io.agentscope.core.message.Msg;
import io.agentscope.core.model.OpenAIChatModel;
import io.agentscope.core.tool.Tool;
import io.agentscope.core.tool.ToolParam;
import io.agentscope.core.tool.Toolkit;

/**
 * 快速创建一个智能体
 */
public class QuickStart {
	public static void main(String[] args) {
		// 准备工具
        Toolkit toolkit = new Toolkit();
        toolkit.registerTool(new SimpleTools());

        OpenAIChatModel model = OpenAIChatModel.builder()
                .apiKey("123456")
                .modelName("Qwen3.6")
                .baseUrl("http://172.17.17.161:8888/v1")
                .endpointPath("/chat/completions")
                .formatter(new OpenAIMultiAgentFormatter())
                .stream(false)
                .build();
        
        // 创建智能体
        ReActAgent jarvis = ReActAgent.builder()
            .name("Jarvis")
            .sysPrompt("你是一个名为 Jarvis 的助手")
            .model(model)
            .toolkit(toolkit)
            .build();

        // 发送消息
        Msg msg = Msg.builder()
            .textContent("你好！Jarvis，现在几点了？")
            .build();

        Msg response = jarvis.call(msg).block();
        System.out.println(response.getTextContent());
	}
}


	//工具类
	class SimpleTools {
	    @Tool(name = "get_time", description = "获取当前时间")
	    public String getTime(
	            @ToolParam(name = "zone", description = "时区，例如：北京") String zone) {
	        return java.time.LocalDateTime.now()
	            .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
	    }
	}
