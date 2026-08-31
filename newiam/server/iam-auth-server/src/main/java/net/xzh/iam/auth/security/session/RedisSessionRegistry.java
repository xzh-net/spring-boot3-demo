package net.xzh.iam.auth.security.session;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.context.ApplicationListener;
import org.springframework.session.events.SessionDestroyedEvent;

import lombok.extern.slf4j.Slf4j;

/**
 * 基于 Redis 的 SessionRegistry 实现，将会话跟踪信息持久化到 Redis。
 * <p>
 * 解决 {@link org.springframework.security.core.session.SessionRegistryImpl}
 * 内存实现重启后在线用户列表清空的问题。
 *
 * <h3>Redis 数据结构</h3>
 * <ul>
 *   <li>{@code sessionreg:session:{sessionId}} → Hash: principalName, authorities, lastRequest</li>
 *   <li>{@code sessionreg:principal:{principalName}} → Set: sessionId 列表</li>
 *   <li>{@code sessionreg:all} → Set: 所有 sessionId</li>
 * </ul>
 *
 * <h3>TTL 策略</h3>
 * <p>所有 key 设置 30 分钟 TTL，与会话超时一致，过期自动清理。
 */
@Slf4j
public class RedisSessionRegistry implements SessionRegistry, ApplicationListener<AbstractSessionEvent> {

	private static final String SESSION_KEY_PREFIX = "sessionreg:session:";
	private static final String PRINCIPAL_KEY_PREFIX = "sessionreg:principal:";
	private static final String ALL_SESSIONS_KEY = "sessionreg:all";
	private static final Duration TTL = Duration.ofMinutes(30);

	private final StringRedisTemplate redisTemplate;

	public RedisSessionRegistry(StringRedisTemplate redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	@Override
	public void registerNewSession(String sessionId, Object principal) {
		if (sessionId == null || principal == null) {
			return;
		}

		// 从 principal 中提取用户名，支持多种类型:
		// - UserDetails: 标准 Spring Security 用户详情
		// - String: 直接是用户名
		// - Authentication: 从 authentication.getPrincipal() 提取
		// - 其他对象: 尝试调用 getName() 或 toString()
		String username = extractUsername(principal);
		if (username == null || username.isBlank()) {
			log.warn("[RedisSessionRegistry] 无法从 principal 提取用户名: {}, 跳过注册", principal.getClass());
			return;
		}

		String authorities = extractAuthorities(principal);

		String sessionKey = SESSION_KEY_PREFIX + sessionId;
		String principalKey = PRINCIPAL_KEY_PREFIX + username;

		// 1. 存储会话信息
		long now = System.currentTimeMillis();
		redisTemplate.opsForHash().put(sessionKey, "principalName", username);
		redisTemplate.opsForHash().put(sessionKey, "sessionId", sessionId);
		redisTemplate.opsForHash().put(sessionKey, "authorities", authorities);
		redisTemplate.opsForHash().put(sessionKey, "creationTime", String.valueOf(now));
		redisTemplate.opsForHash().put(sessionKey, "lastRequest", String.valueOf(now));
		redisTemplate.expire(sessionKey, TTL);

		// 2. 维护 principal → sessionId 反向索引
		redisTemplate.opsForSet().add(principalKey, sessionId);
		redisTemplate.expire(principalKey, TTL);

		// 3. 维护全局 sessionId 集合
		redisTemplate.opsForSet().add(ALL_SESSIONS_KEY, sessionId);

		log.info("[RedisSessionRegistry] 注册会话: principal={}, sessionId={}", username, sessionId);
	}

	/**
	 * 从 principal 对象中提取用户名.
	 */
	private String extractUsername(Object principal) {
		if (principal instanceof UserDetails ud) {
			return ud.getUsername();
		}
		if (principal instanceof String s) {
			return s;
		}
		// 尝试处理 Authentication 对象
		if (principal instanceof org.springframework.security.core.Authentication auth) {
			Object innerPrincipal = auth.getPrincipal();
			if (innerPrincipal instanceof UserDetails ud) {
				return ud.getUsername();
			}
			if (innerPrincipal instanceof String s) {
				return s;
			}
			if (innerPrincipal != null) {
				return innerPrincipal.toString();
			}
			return auth.getName();
		}
		// 其他情况: 使用 toString()
		return principal.toString();
	}

	/**
	 * 从 principal 对象中提取权限列表.
	 */
	private String extractAuthorities(Object principal) {
		if (principal instanceof UserDetails ud) {
			return ud.getAuthorities().stream()
					.map(GrantedAuthority::getAuthority)
					.collect(Collectors.joining(","));
		}
		if (principal instanceof org.springframework.security.core.Authentication auth) {
			return auth.getAuthorities().stream()
					.map(GrantedAuthority::getAuthority)
					.collect(Collectors.joining(","));
		}
		return "";
	}

	@Override
	public void removeSessionInformation(String sessionId) {
		if (sessionId == null) {
			return;
		}
		String sessionKey = SESSION_KEY_PREFIX + sessionId;
		Object principalName = redisTemplate.opsForHash().get(sessionKey, "principalName");

		// 1. 删除会话信息
		redisTemplate.delete(sessionKey);

		// 2. 从全局集合移除
		redisTemplate.opsForSet().remove(ALL_SESSIONS_KEY, sessionId);

		// 3. 从 principal 反向索引移除
		if (principalName != null) {
			String principalKey = PRINCIPAL_KEY_PREFIX + principalName;
			redisTemplate.opsForSet().remove(principalKey, sessionId);
			// 清理空集合
			Long remaining = redisTemplate.opsForSet().size(principalKey);
			if (remaining != null && remaining == 0) {
				redisTemplate.delete(principalKey);
			}
		}
		log.info("[RedisSessionRegistry] 移除会话: sessionId={}, principal={}", sessionId, principalName);
	}

	@Override
	public SessionInformation getSessionInformation(String sessionId) {
		if (sessionId == null) {
			return null;
		}
		String sessionKey = SESSION_KEY_PREFIX + sessionId;
		Map<Object, Object> entries = redisTemplate.opsForHash().entries(sessionKey);
		if (entries.isEmpty()) {
			return null;
		}
		// 仅当会话未被标记为过期时，才更新 lastRequest 并续期 TTL
		// （过期的会话不应续期，否则永远不会被清理）
		if (!"true".equals(getStr(entries, "expired"))) {
			long now = System.currentTimeMillis();
			redisTemplate.opsForHash().put(sessionKey, "lastRequest", String.valueOf(now));
			redisTemplate.expire(sessionKey, TTL);

			// 续期 principal 索引
			Object principalName = entries.get("principalName");
			if (principalName != null) {
				redisTemplate.expire(PRINCIPAL_KEY_PREFIX + principalName, TTL);
			}
		}

		return buildSessionInformation(entries);
	}

	/**
	 * 标记会话为过期（持久化到 Redis）.
	 * <p>
	 * 与 {@link SessionInformation#expireNow()} 不同，此方法将过期状态持久化到 Redis，
	 * 确保后续 {@link #getSessionInformation(String)} 重建的对象仍能被检测到为过期。
	 * <p>
	 * 用于"强制下线"场景：标记过期后，{@link net.xzh.iam.auth.security.web.SessionExpirationFilter}
	 * 会在用户下次请求时检测到过期状态，销毁 HttpSession 并清理记录。
	 *
	 * @param sessionId 会话 ID
	 */
	public void markSessionExpired(String sessionId) {
		if (sessionId == null) {
			return;
		}
		String sessionKey = SESSION_KEY_PREFIX + sessionId;
		redisTemplate.opsForHash().put(sessionKey, "expired", "true");
		log.info("[RedisSessionRegistry] 标记会话过期: sessionId={}", sessionId);
	}

	/**
	 * 获取会话创建时间 (登录时间).
	 * <p>
	 * 与 {@link #getSessionInformation(String)} 返回的 lastRequest (最后访问时间) 不同,
	 * creationTime 在 {@link #registerNewSession} 时写入, 后续不会更新.
	 *
	 * @param sessionId 会话 ID
	 * @return 创建时间的毫秒时间戳, 若会话不存在或无 creationTime 则返回 null
	 */
	public Long getCreationTime(String sessionId) {
		if (sessionId == null) {
			return null;
		}
		Object val = redisTemplate.opsForHash().get(SESSION_KEY_PREFIX + sessionId, "creationTime");
		if (val != null) {
			try {
				return Long.parseLong(val.toString());
			} catch (NumberFormatException e) {
				return null;
			}
		}
		return null;
	}

	@Override
	public List<Object> getAllPrincipals() {
		Set<String> sessionIds = redisTemplate.opsForSet().members(ALL_SESSIONS_KEY);
		if (sessionIds == null || sessionIds.isEmpty()) {
			return Collections.emptyList();
		}
		// 收集所有 principalName (去重)
		Set<String> principalNames = new LinkedHashSet<>();
		for (String sessionId : sessionIds) {
			Object name = redisTemplate.opsForHash().get(SESSION_KEY_PREFIX + sessionId, "principalName");
			if (name != null) {
				principalNames.add(name.toString());
			}
		}
		// 为每个 principalName 重建 UserDetails 对象
		List<Object> result = new ArrayList<>();
		for (String name : principalNames) {
			UserDetails user = rebuildUser(name);
			if (user != null) {
				result.add(user);
			}
		}
		return result;
	}

	@Override
	public List<SessionInformation> getAllSessions(Object principal, boolean includeExpired) {
		String username = extractUsername(principal);
		if (username == null) {
			return Collections.emptyList();
		}
		String principalKey = PRINCIPAL_KEY_PREFIX + username;
		Set<String> sessionIds = redisTemplate.opsForSet().members(principalKey);
		if (sessionIds == null || sessionIds.isEmpty()) {
			return Collections.emptyList();
		}
		List<SessionInformation> result = new ArrayList<>();
		for (String sessionId : sessionIds) {
			String sessionKey = SESSION_KEY_PREFIX + sessionId;
			Map<Object, Object> entries = redisTemplate.opsForHash().entries(sessionKey);
			if (!entries.isEmpty()) {
				SessionInformation info = buildSessionInformation(entries);
				// 按 includeExpired 参数过滤：不包含过期会话时，跳过已标记为过期的
				if (!includeExpired && info.isExpired()) {
					continue;
				}
				result.add(info);
			}
		}
		return result;
	}

	@Override
	public void refreshLastRequest(String sessionId) {
		if (sessionId == null) {
			return;
		}
		String sessionKey = SESSION_KEY_PREFIX + sessionId;
		if (Boolean.TRUE.equals(redisTemplate.hasKey(sessionKey))) {
			redisTemplate.opsForHash().put(sessionKey, "lastRequest", String.valueOf(System.currentTimeMillis()));
			redisTemplate.expire(sessionKey, TTL);
		}
	}

	/**
	 * 监听会话销毁事件，自动清理 Redis 中的会话跟踪记录。
	 * <p>
	 * 同时兼容 Spring Security 的 {@link AbstractSessionEvent}
	 * 和 Spring Session 的 {@link SessionDestroyedEvent}。
	 */
	@Override
	public void onApplicationEvent(AbstractSessionEvent event) {
		// Spring Security 事件
		String sessionId = extractSessionId(event);
		if (sessionId != null) {
			log.debug("[RedisSessionRegistry] 收到会话销毁事件: sessionId={}", sessionId);
			removeSessionInformation(sessionId);
		}
	}

	/**
	 * 处理 Spring Session 的 SessionDestroyedEvent。
	 * <p>
	 * 通过单独的 ApplicationListener 监听，避免类加载问题。
	 */
	public void onSessionDestroyed(SessionDestroyedEvent event) {
		String sessionId = event.getSessionId();
		if (sessionId != null) {
			log.debug("[RedisSessionRegistry] Spring Session 销毁事件: sessionId={}", sessionId);
			removeSessionInformation(sessionId);
		}
	}

	// ==================== 内部方法 ====================

	/**
	 * 从 Redis Hash 构建 SessionInformation 对象。
	 */
	private SessionInformation buildSessionInformation(Map<Object, Object> entries) {
		String sessionId = getStr(entries, "sessionId");
		String principalName = getStr(entries, "principalName");
		String authoritiesStr = getStr(entries, "authorities");
		long lastRequestMillis = entries.containsKey("lastRequest")
				? Long.parseLong(getStr(entries, "lastRequest"))
				: System.currentTimeMillis();

		List<GrantedAuthority> authorities = parseAuthorities(authoritiesStr);
		UserDetails principal = User.withUsername(principalName)
				.password("[PROTECTED]")
				.authorities(authorities)
				.build();

		SessionInformation info = new SessionInformation(principal, sessionId, new Date(lastRequestMillis));
		// 如果 Redis 中标记了 expired=true，恢复过期状态
		if ("true".equals(getStr(entries, "expired"))) {
			info.expireNow();
		}
		return info;
	}

	/**
	 * 根据 principalName 从 Redis 重建 UserDetails 对象。
	 */
	private UserDetails rebuildUser(String principalName) {
		String principalKey = PRINCIPAL_KEY_PREFIX + principalName;
		Set<String> sessionIds = redisTemplate.opsForSet().members(principalKey);
		if (sessionIds == null || sessionIds.isEmpty()) {
			return null;
		}
		// 取第一个 session 的 authorities
		String firstSessionId = sessionIds.iterator().next();
		Object authoritiesObj = redisTemplate.opsForHash().get(SESSION_KEY_PREFIX + firstSessionId, "authorities");
		String authoritiesStr = authoritiesObj != null ? authoritiesObj.toString() : "";
		return User.withUsername(principalName)
				.password("[PROTECTED]")
				.authorities(parseAuthorities(authoritiesStr))
				.build();
	}

	private String extractSessionId(AbstractSessionEvent event) {
		// Spring Security 的 HttpSessionDestroyedEvent
		try {
			var method = event.getClass().getMethod("getId");
			Object id = method.invoke(event);
			return id != null ? id.toString() : null;
		} catch (Exception e) {
			return null;
		}
	}

	private List<GrantedAuthority> parseAuthorities(String authoritiesStr) {
		if (authoritiesStr == null || authoritiesStr.isEmpty()) {
			return Collections.emptyList();
		}
		return Arrays.stream(authoritiesStr.split(","))
				.filter(s -> !s.isEmpty())
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

	private String getStr(Map<Object, Object> entries, String key) {
		Object val = entries.get(key);
		return val != null ? val.toString() : "";
	}
}
