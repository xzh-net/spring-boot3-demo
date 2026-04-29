package net.xzh.agent.config;

import java.util.Properties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.ai.AiFactory;
import com.alibaba.nacos.api.ai.AiService;
import com.alibaba.nacos.api.exception.NacosException;

import io.agentscope.core.ReActAgent;
import io.agentscope.core.a2a.agent.A2aAgent;
import io.agentscope.core.a2a.agent.card.AgentCardResolver;
import io.agentscope.core.agent.Agent;
import io.agentscope.core.formatter.openai.OpenAIMultiAgentFormatter;
import io.agentscope.core.memory.InMemoryMemory;
import io.agentscope.core.model.OpenAIChatModel;
import io.agentscope.core.nacos.a2a.discovery.NacosAgentCardResolver;
import io.agentscope.core.tool.Toolkit;
import io.agentscope.spring.boot.agui.common.AguiAgentRegistryCustomizer;
import net.xzh.agent.tools.ExampleTools;

/**
 * 智能体配置
 */
@Configuration
public class AgentConfiguration {

	/**
	 * 注册了3个智能体
	 * 
	 * @return
	 */
	@Bean
	public AguiAgentRegistryCustomizer aguiAgentRegistryCustomizer() {
		AguiAgentRegistryCustomizer aguiAgentRegistryCustomizer = registry -> {
			// 有工具的默认智能体
			registry.registerFactory("default", this::createDefaultAgent);
			// 没有工具的对话智能体
			registry.registerFactory("chat", this::createChatAgent);
			// 远端获取智能体
			registry.registerFactory("robot", this::createRobotAgent);
		};
		return aguiAgentRegistryCustomizer;
	}

	/**
	 * 从远端注册智能体
	 * 
	 * @return
	 */
	private Agent createRobotAgent() {
		AgentCardResolver agentCardResolver = null;
		try {
			agentCardResolver = new NacosAgentCardResolver(buildNacosClient());
		} catch (NacosException e) {
			e.printStackTrace();
		}
		A2aAgent agent = A2aAgent.builder().name("agentscope-a2a-example-agent").agentCardResolver(agentCardResolver)
				.build();
		return agent;
	}

	private static AiService buildNacosClient() throws NacosException {
		String nacosServerAddr = "172.17.17.161:8848";
		String nacosUsername = "nacos";
		String nacosPassword = "nacos";
		Properties properties = new Properties();
		properties.put(PropertyKeyConst.SERVER_ADDR, nacosServerAddr);
		if (nacosUsername != null && nacosPassword != null) {
			properties.put(PropertyKeyConst.USERNAME, nacosUsername);
			properties.put(PropertyKeyConst.PASSWORD, nacosPassword);
		}
		return AiFactory.createAiService(properties);
	}

	/**
	 * 有工具的默认智能体
	 * 
	 * @return
	 */
	private Agent createDefaultAgent() {
		String apiKey = getRequiredApiKey();
		// Create toolkit with example tools
		Toolkit toolkit = new Toolkit();
		toolkit.registerTool(new ExampleTools());

		// Create the agent
		return ReActAgent.builder().name("AG-UI Assistant")
				.sysPrompt("You are a helpful AI assistant exposed via the AG-UI protocol. "
						+ "You can help users with various tasks including weather queries "
						+ "and calculations. Be concise and helpful in your responses.")
				.model(OpenAIChatModel.builder().apiKey("123456").modelName("Qwen3.6")
						.baseUrl("http://172.17.17.161:8888/v1").endpointPath("/chat/completions")
						.formatter(new OpenAIMultiAgentFormatter()).stream(true).build())
				.toolkit(toolkit).memory(new InMemoryMemory()).maxIters(10).build();
	}

	/**
	 * 没有工具的对话智能体
	 * 
	 * @return
	 */
	private Agent createChatAgent() {
		String apiKey = getRequiredApiKey();
		return ReActAgent.builder().name("Chat Assistant")
				.sysPrompt("You are a friendly conversational assistant. "
						+ "Engage in natural conversation and help users " + "with general questions and discussions.")
				.model(OpenAIChatModel.builder().apiKey("123456").modelName("Qwen3.6")
						.baseUrl("http://172.17.17.161:8888/v1").endpointPath("/chat/completions")
						.formatter(new OpenAIMultiAgentFormatter()).stream(true).build())
				.memory(new InMemoryMemory()).maxIters(1).build();
	}

	private String getRequiredApiKey() {
		String apiKey = System.getenv("DASHSCOPE_API_KEY") + "123456";
		if (apiKey == null || apiKey.isEmpty()) {
			throw new IllegalStateException("DASHSCOPE_API_KEY environment variable is required. "
					+ "Please set it before starting the application.");
		}
		return apiKey;
	}
}
