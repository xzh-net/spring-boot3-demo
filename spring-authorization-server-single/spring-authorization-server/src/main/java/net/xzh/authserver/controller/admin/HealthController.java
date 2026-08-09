package net.xzh.authserver.controller.admin;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/health")
public class HealthController {

    private final JdbcTemplate jdbcTemplate;
    private final StringRedisTemplate redisTemplate;

    public HealthController(JdbcTemplate jdbcTemplate, StringRedisTemplate redisTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        this.redisTemplate = redisTemplate;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "UP");
        result.put("timestamp", Instant.now().toString());

        Map<String, Object> components = new LinkedHashMap<>();
        components.put("application", "UP");

        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            components.put("mysql", "UP");
        } catch (Exception e) {
            log.error("MySQL 健康检查失败", e);
            components.put("mysql", "DOWN: " + e.getMessage());
            result.put("status", "DEGRADED");
        }

        try {
            String pong = redisTemplate.getConnectionFactory()
                    .getConnection().ping();
            components.put("redis", "UP (" + pong + ")");
        } catch (Exception e) {
            log.error("Redis 健康检查失败", e);
            StringBuilder sb = new StringBuilder(e.getMessage());
            Throwable cause = e.getCause();
            while (cause != null) {
                sb.append(" → ").append(cause.getClass().getSimpleName()).append(": ").append(cause.getMessage());
                cause = cause.getCause();
            }
            components.put("redis", "DOWN: " + sb);
            result.put("status", "DEGRADED");
        }

        result.put("components", components);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> info() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", "Spring Authorization Server Single");
        info.put("version", "1.0.0");
        info.put("spring_boot", "4.1.0");
        info.put("java", System.getProperty("java.version"));
        info.put("endpoints", Map.of(
                "authorization", "/oauth2/authorize",
                "token", "/oauth2/token",
                "device_authorization", "/oauth2/device_authorization",
                "device_verification", "/oauth2/device/verify",
                "jwks_uri", "/oauth2/jwks"
        ));
        return ResponseEntity.ok(info);
    }
}
