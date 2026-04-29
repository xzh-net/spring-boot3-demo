package net.xzh.agent.client;


import java.util.List;

import io.a2a.spec.AgentCapabilities;
import io.a2a.spec.AgentCard;
import io.agentscope.core.a2a.agent.A2aAgent;
import io.agentscope.core.message.Msg;
import io.agentscope.core.message.MsgRole;
import io.agentscope.core.message.TextBlock;

/**
 * 4种方式之1：直接提供
 */
public class BaseA2aAgentClient {
	
	public static void main(String[] args) {
		AgentCard ac = mockAgentCard();
        A2aAgent agent = A2aAgent.builder()
                .agentCard(ac)
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
