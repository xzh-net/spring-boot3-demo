package net.xzh.agent.tools;

import io.agentscope.core.message.ToolResultBlock;
import io.agentscope.core.tool.Tool;
import io.agentscope.core.tool.ToolParam;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;

/**
 * 工具类
 */
public class ExampleTools {

	private final Random random = new Random();

	/**
	 * 获取天气结果
	 * 
	 * @param city
	 * @return
	 */
	@Tool(name = "get_weather", description = "Get current weather information for a city")
	public ToolResultBlock getWeather(
			@ToolParam(name = "city", description = "The city name (e.g., 'Beijing', 'New York')") String city) {
		// Mock weather data
		String[] conditions = { "Sunny", "Cloudy", "Partly Cloudy", "Rainy", "Overcast" };
		String condition = conditions[random.nextInt(conditions.length)];
		int temperature = random.nextInt(35) + 5; // 5-40 degrees
		int humidity = random.nextInt(60) + 30; // 30-90%

		String result = String.format("Weather in %s:\n- Condition: %s\n- Temperature: %d°C\n- Humidity: %d%%", city,
				condition, temperature, humidity);
		return ToolResultBlock.text(result);
	}

	/**
	 * 获取当前日期和时间
	 * 
	 * @return
	 */
	@Tool(name = "get_current_time", description = "Get the current date and time")
	public ToolResultBlock getCurrentTime() {
		LocalDateTime now = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
		return ToolResultBlock.text("Current time: " + now.format(formatter));
	}

	/**
	 * 对指定区域进行检查，并通过电子邮件发送报告
	 * 
	 * @param region
	 * @return
	 */
	@Tool(name = "exec_check", description = "对指定区域进行检查，并通过电子邮件发送报告")
	public String getTime(@ToolParam(name = "region", description = "待检查区域（例如：'开发环境'、'生产环境'、'测试环境'）") String region) {
		return "success";
	}

}
