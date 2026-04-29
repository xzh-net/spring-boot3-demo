package net.xzh.agent.client;


import java.util.List;

import io.a2a.spec.AgentCapabilities;
import io.a2a.spec.AgentCard;
import io.agentscope.core.a2a.agent.A2aAgent;
import io.agentscope.core.message.Msg;
import io.agentscope.core.message.MsgRole;
import io.agentscope.core.message.TextBlock;

/**
 * 4种方式之4：自定义函数式接口，最灵活，按照业务规则动态返回AgentCard
 */
public class LambdaA2aAgentClient {
	
	public static void main(String[] args) {
		
		A2aAgent agent = A2aAgent.builder()
				.name("lambda-agent")
                .agentCardResolver(LambdaA2aAgentClient::customGetAgentCard)  // 方法引用更简洁
                .build();

        Msg userMsg =
                Msg.builder()
                        .role(MsgRole.USER)
                        .content(TextBlock.builder().text("讲个笑话").build())
                        .build();
        
		Msg response = agent.call(userMsg).block();
		System.out.println(response.getContent());
	}

	/**
	 * 自定义解析器：根据 agentName 动态返回 AgentCard
	 * @param agentName
	 * @return
	 */
    private static AgentCard customGetAgentCard(String agentName) {
        // 根据名称动态构建（如不同名称对应不同配置）可从数据库、配置中心等获取
        if ("lambda-agent".equals(agentName)) {
            return mockAgentCard();
        }
		return mockAgentCard();
    }

	
	/**
	 * 手动构建一个agentCard
	 * @return
	 */
	private static AgentCard mockAgentCard() {
        return new AgentCard.Builder()
                .name("test-agent")
                .description("test")
                .capabilities(new AgentCapabilities.Builder().build())
                .defaultInputModes(List.of())
                .defaultOutputModes(List.of())
                .url("http://127.0.0.1:8888")
                .preferredTransport("JSONRPC")
                .version("1.0.0")
                .skills(List.of())
                .build();
    }
}
