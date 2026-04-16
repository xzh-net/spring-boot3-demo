package net.xzh.mcp.server;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

import net.xzh.mcp.filter.LoggingFilter;

@SpringBootApplication
public class McpServerApplication {


    public static void main(String[] args) {
        SpringApplication.run(McpServerApplication.class, args);
    }

	@Bean
	public ToolCallbackProvider weatherTools(WeatherService weatherService) {
		return MethodToolCallbackProvider.builder().toolObjects(weatherService).build();
	}
	
	/**
	 * 注册请求头过滤器，专门用来调试网关代理后参数异常情况，生产环境关闭
	 * @return
	 */
	@Bean
	public FilterRegistrationBean<LoggingFilter> loggingFilter() {
	    FilterRegistrationBean<LoggingFilter> registration = new FilterRegistrationBean<>();
	    registration.setFilter(new LoggingFilter());
	    registration.addUrlPatterns("/mcp/*");
	    return registration;
	}
}
