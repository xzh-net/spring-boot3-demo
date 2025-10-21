package openai.image.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.ai.image.ImageGeneration;
import org.springframework.ai.image.ImageModel;
import org.springframework.ai.image.ImagePrompt;
import org.springframework.ai.image.ImageResponse;
import org.springframework.ai.openai.OpenAiImageModel;
import org.springframework.ai.openai.OpenAiImageOptions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
* @Author: xzh
* @Date: 2024-12-16
*/

@RestController
@RequestMapping("/openai/image-client")
public class ImageModelController {

	private final ImageModel openaiImageModel;

	public ImageModelController(OpenAiImageModel openaiImageModel) {
		this.openaiImageModel = openaiImageModel;
	}
	
	/**
	 * 运行时构建参数
	 */
	@GetMapping("/simple")
	public List<String> simple() {
		OpenAiImageOptions options = OpenAiImageOptions.builder()
                .quality("hd")
                .N(4)
                .height(1024)
                .width(1024)
                .build();
        ImagePrompt imagePrompt = new ImagePrompt("浩瀚宇宙", options);
        
        ImageResponse response  = openaiImageModel.call(imagePrompt);
        // 解析图片URL
        List<String> imageUrls = new ArrayList<>();
        for (ImageGeneration image : response.getResults()) {
            imageUrls.add(image.getOutput().getUrl());
        }
        return imageUrls;
	}
}
