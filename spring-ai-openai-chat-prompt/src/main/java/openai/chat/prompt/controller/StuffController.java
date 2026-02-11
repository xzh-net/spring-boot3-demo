
package openai.chat.prompt.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.prompt.PromptTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/prompt/ai")
public class StuffController {

	private final ChatClient chatClient;

	@Value("classpath:/docs/wikipedia-curling.md")
	private Resource docsToStuffResource;

	@Value("classpath:/prompts/qa-prompt.st")
	private Resource qaPromptResource;

	@Autowired
	public StuffController(ChatClient.Builder builder) {
		this.chatClient = builder.build();
	}

	/**
	 * 演示使用特定的 prompt 上下文信息以增强大模型的回答。
	 */
	@GetMapping(value = "/stuff")
	public Flux<String> completion(
			@RequestParam(
					value = "message",
					required = false,
					defaultValue = "Which athletes won the mixed doubles gold medal in curling at the 2022 Winter Olympics?") String message,
			@RequestParam(value = "stuffit", defaultValue = "false") boolean stuffit
	) {

		PromptTemplate promptTemplate = new PromptTemplate(qaPromptResource);

		Map<String, Object> map = new HashMap<>();
		map.put("question", message);

		// 是否填充 prompt 上下文，以增强大模型回答。
		if (stuffit) {
			map.put("context", docsToStuffResource);
		}
		else {
			map.put("context", "");
		}

		return chatClient.prompt(promptTemplate.create(map))
				.stream().content();
	}

}
