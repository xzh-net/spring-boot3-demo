package net.xzh.milvus.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.milvus.v2.service.vector.response.GetResp;
import io.milvus.v2.service.vector.response.SearchResp;
import net.xzh.milvus.model.Product;
import net.xzh.milvus.service.MilvusService;

@RestController
@RequestMapping("/milvus")
public class MilvusController {
	
    @Autowired
    private MilvusService milvusService;

    @GetMapping("/createCollection")
    public String createCollection() {
        milvusService.createCollection();
        return "创建成功";
    }

    @GetMapping("/insertProducts")
    public String insertProducts() {
        List<Product> products = Arrays.asList(
            createProduct("1", "男士纯棉圆领短袖T恤 白色 夏季休闲"),
            createProduct("2", "女士碎花雪纺连衣裙 长款 春装"),
            createProduct("3", "男款运动速干短袖 黑色 透气健身服"),
            createProduct("4", "女童蕾丝公主裙 粉色 儿童节礼服"),
            createProduct("5", "男士条纹POLO衫 商务休闲 棉质")
        );
        milvusService.batchInsertProducts(products);
        return "插入成功";
    }  
    
    @GetMapping("/getProduct")
    public GetResp getProduct(@RequestParam(name = "id") String id) {
        return milvusService.getProduct(id);
    }
    
    @GetMapping("/queryVector")
    public List<List<SearchResp.SearchResult>> queryVector(
            @RequestParam(name = "queryText", defaultValue = "男款透气运动T恤") String queryText) {
        return milvusService.queryVector(queryText);
    }
    
    private Product createProduct(String id, String title) {
        Product product = new Product();
        product.setId(id);
        product.setTitle(title);
        return product;
    }
}