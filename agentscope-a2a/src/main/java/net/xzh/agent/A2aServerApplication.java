package net.xzh.agent;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import io.agentscope.core.tool.Toolkit;
import net.xzh.agent.tools.ExampleTools;

/**
 * 分布式智能
 */

@SpringBootApplication
public class A2aServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(A2aServerApplication.class, args);
    }

    /**
     * Optional, if you want to register tools for the agent.
     */
    @Bean
    public Toolkit toolkit() {
        Toolkit toolkit = new Toolkit();
        toolkit.registerTool(new ExampleTools());
        return toolkit;
    }
    
}
