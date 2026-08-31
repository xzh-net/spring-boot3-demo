package net.xzh.mcp.client;

import java.util.Map;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

/**
 * @author xzh
 */
public class StreamableHttpClient {

	public static void main(String[] args) {
		HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder("http://localhost:8080")
				.build();
		var client = McpClient.sync(transport).build();
		client.initialize();
		client.ping();

		CallToolResult weatherResult = client.callTool(new CallToolRequest("getWeather", Map.of("cityName", "大连")));
		System.out.println("weatherResult Response = " + weatherResult);
		client.closeGracefully();
	}

}
