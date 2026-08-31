package net.xzh.mcp.service;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

@Service
public class WeatherService {

	@Tool(description = "Get weather information by city name")
	public String getWeather(String cityName) {
		return String.format("""
				%s ,Temperature: %s ~ %s ,Wind: %s ,windDirection: %s""", cityName, 9, 17.2, 1.2, "微风");
	}

}