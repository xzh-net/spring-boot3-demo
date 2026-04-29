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

package net.xzh.agent.client;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.ai.AiFactory;
import com.alibaba.nacos.api.ai.AiService;
import com.alibaba.nacos.api.exception.NacosException;
import io.agentscope.core.a2a.agent.A2aAgent;
import io.agentscope.core.a2a.agent.card.AgentCardResolver;
import io.agentscope.core.nacos.a2a.discovery.NacosAgentCardResolver;
import java.util.Properties;

/**
 * 4种方式之3：从 Nacos 中发现服务
 */
public class NacosA2aAgentClient {

    public static void main(String[] args) throws NacosException {
        // Create agent card resolver by Nacos.
        AgentCardResolver agentCardResolver = new NacosAgentCardResolver(buildNacosClient());
        // Create A2aAgent
        A2aAgent agent =
                A2aAgent.builder()
                        .name("agentscope-a2a-example-agent")
                        .agentCardResolver(agentCardResolver)
                        .build();
        A2aAgentExampleRunner exampleRunner = new A2aAgentExampleRunner(agent);
        exampleRunner.startExample();
    }

    private static AiService buildNacosClient() throws NacosException {
        String nacosServerAddr = System.getenv("NACOS_SERVER_ADDR");
        if (nacosServerAddr == null) {
            nacosServerAddr = "172.17.17.161:8848";
        }
        String nacosUsername = System.getenv("NACOS_USERNAME");
        String nacosPassword = System.getenv("NACOS_PASSWORD");
        Properties properties = new Properties();
        properties.put(PropertyKeyConst.SERVER_ADDR, nacosServerAddr);
        if (nacosUsername != null && nacosPassword != null) {
            properties.put(PropertyKeyConst.USERNAME, nacosUsername);
            properties.put(PropertyKeyConst.PASSWORD, nacosPassword);
        }
        return AiFactory.createAiService(properties);
    }
}
