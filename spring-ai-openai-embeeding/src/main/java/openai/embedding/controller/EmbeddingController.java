package openai.embedding.controller;

import java.util.List;
import java.util.Map;

import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingRequest;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.ai.openai.OpenAiEmbeddingOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: xzh
 * @Date: 2025-09-09
 */

@SuppressWarnings("rawtypes")
@RestController
@RequestMapping("/embedding")
public class EmbeddingController {

	private final EmbeddingModel OpenAiEmbeddingModel;

	@Autowired
	public EmbeddingController(EmbeddingModel OpenAiEmbeddingModel) {
		this.OpenAiEmbeddingModel = OpenAiEmbeddingModel;
	}
	
	/*
	 * 返回向量数据
	 */
	@GetMapping("/vectordata")
	public Map vectordata(@RequestParam(value = "message", defaultValue = "体恤衫") String message) {
		List<float[]> embed = this.OpenAiEmbeddingModel.embed(List.of(message));
		return Map.of("embedding", embed);
	}
	
	/*
	 * 返回向量数据+元数据
	 */
	@GetMapping("/metadata")
	public Map metadata(@RequestParam(value = "message", defaultValue = "牛仔裤") String message) {
		EmbeddingResponse embeddingResponse = this.OpenAiEmbeddingModel.embedForResponse(List.of(message));
		return Map.of("embedding", embeddingResponse);
	}

	@GetMapping("/custom")
	public Map custom() {
		EmbeddingResponse embeddingResponse = OpenAiEmbeddingModel
				.call(new EmbeddingRequest(List.of("连衣裙", "晚匣子"),
						OpenAiEmbeddingOptions.builder().model("Qwen3-Embedding-8B").build()));
		return Map.of("embedding", embeddingResponse);
	}
}
