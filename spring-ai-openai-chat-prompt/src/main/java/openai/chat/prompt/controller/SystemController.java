
package openai.chat.prompt.controller;

import java.util.List;
import java.util.Map;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.chat.prompt.SystemPromptTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/example/ai")
public class SystemController {

	private final ChatClient chatClient;

	/**
	 * 加载 System prompt tmpl.
	 */
	@Value("classpath:/prompts/system-message.st")
	private Resource systemResource;

	@Autowired
	public SystemController(ChatClient.Builder builder) {
		this.chatClient = builder.build();
	}

	@GetMapping("/roles")
	public Flux<String> generate(
			@RequestParam(
					value = "message",
					required = false,
					defaultValue = "说出2008年北京奥运会中国队第一块金牌获得者，并描述一下他的职业历程") String message,
			@RequestParam(value = "name", required = false, defaultValue = "万事通") String name,
			@RequestParam(value = "voice", required = false, defaultValue = "讲解员") String voice
	) {

		// 用户输入
		UserMessage userMessage = new UserMessage(message);

		// 使用 System prompt tmpl
		SystemPromptTemplate systemPromptTemplate = new SystemPromptTemplate(systemResource);
		// 填充 System prompt 中的变量值
		Message systemMessage = systemPromptTemplate.createMessage(Map.of("name", name, "voice", voice));

		// 调用大模型
		return chatClient.prompt(
						new Prompt(List.of(
								userMessage,
								systemMessage)))
				.stream().content();
	}

}
