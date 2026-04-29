package net.xzh.agent.client;

import io.agentscope.core.a2a.agent.A2aAgent;
import io.agentscope.core.a2a.agent.card.AgentCardResolver;
import io.agentscope.core.a2a.agent.card.WellKnownAgentCardResolver;
import io.agentscope.core.message.Msg;
import io.agentscope.core.message.MsgRole;
import io.agentscope.core.message.TextBlock;

/**
 * 4种方式之2：从 well-known 路径发现服务
 * 
 */
public class SimpleA2aAgentClient {

    public static void main(String[] args) {
        // 默认 well-known uri 获取
        AgentCardResolver agentCardResolver =
                WellKnownAgentCardResolver.builder().baseUrl("http://localhost:8888").build();
        
        // 自定义 well-known uri 获取
        AgentCardResolver agentCardResolver2 =
                WellKnownAgentCardResolver.builder().baseUrl("http://localhost:8888").relativeCardPath("/.well-known/agent-card.json").build();
        
        // Create A2aAgent
        A2aAgent agent =
                A2aAgent.builder()
                        .name("agentscope-a2a-example-agent")
                        .agentCardResolver(agentCardResolver2)
                        .build();
        Msg userMsg =
                Msg.builder()
                        .role(MsgRole.USER)
                        .content(TextBlock.builder().text("生产环境巡检").build())
                        .build();
		Msg response = agent.call(userMsg).block();
		System.out.println(response.getContent());

		
//        A2aAgentExampleRunner exampleRunner = new A2aAgentExampleRunner(agent);
//        exampleRunner.startExample();
        
    }
}
