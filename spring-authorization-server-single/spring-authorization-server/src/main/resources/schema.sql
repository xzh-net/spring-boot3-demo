-- ============================================================
-- Spring Authorization Server 单体版 - MySQL 8 建表脚本
-- 数据库: oauth2_server
-- ============================================================

CREATE DATABASE IF NOT EXISTS oauth2_server
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE oauth2_server;

-- ------------------------------------------------------------
-- 1. 系统用户表
-- ------------------------------------------------------------
DROP TABLE IF EXISTS sys_user;
CREATE TABLE sys_user (
    id                     BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT '主键ID',
    username               VARCHAR(100) NOT NULL UNIQUE COMMENT '登录用户名',
    password               VARCHAR(200) NOT NULL COMMENT 'BCrypt 加密后的密码',
    nickname               VARCHAR(100) DEFAULT NULL COMMENT '用户昵称',
    email                  VARCHAR(200) DEFAULT NULL COMMENT '电子邮箱',
    phone                  VARCHAR(50)  DEFAULT NULL COMMENT '手机号码',
    avatar                 VARCHAR(500) DEFAULT NULL COMMENT '头像 URL',
    role                   VARCHAR(30)  NOT NULL DEFAULT 'ROLE_USER' COMMENT '角色: ROLE_ADMIN / ROLE_USER',
    enabled                TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '是否启用 (1=启用, 0=禁用)',
    account_non_expired    TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '账号是否未过期 (1=未过期, 0=已过期)',
    account_non_locked     TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '账号是否未锁定 (1=未锁定, 0=已锁定)',
    credentials_non_expired TINYINT(1)  NOT NULL DEFAULT 1 COMMENT '凭证是否未过期 (1=未过期, 0=已过期)',
    create_time            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    update_time            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统用户表';


-- ------------------------------------------------------------
-- 2. OAuth2 客户端注册表
--    参考 Spring Authorization Server 官方 JdbcRegisteredClientRepository
-- ------------------------------------------------------------
DROP TABLE IF EXISTS oauth2_registered_client;
CREATE TABLE oauth2_registered_client (
    id                            VARCHAR(100)  NOT NULL PRIMARY KEY COMMENT '客户端主键ID (UUID)',
    client_id                     VARCHAR(100)  NOT NULL COMMENT '客户端标识符 (对外公开的ID)',
    client_id_issued_at           DATETIME      DEFAULT CURRENT_TIMESTAMP COMMENT '客户端ID签发时间',
    client_secret                 VARCHAR(200)  DEFAULT NULL COMMENT '客户端密钥 (BCrypt 加密), PKCE 客户端可为空',
    client_secret_expires_at      DATETIME      DEFAULT NULL COMMENT '客户端密钥过期时间 (NULL=永不过期)',
    client_name                   VARCHAR(200)  DEFAULT NULL COMMENT '客户端名称 (展示用)',
    client_authentication_methods VARCHAR(1000) NOT NULL COMMENT '客户端认证方式: client_secret_basic,client_secret_post,none,private_key_jwt 等',
    authorization_grant_types     VARCHAR(1000) NOT NULL COMMENT '授权类型: authorization_code,client_credentials,refresh_token,password,urn:ietf:params:oauth:grant-type:device_code',
    redirect_uris                 VARCHAR(1000) DEFAULT NULL COMMENT '回调地址列表 (逗号分隔)',
    post_logout_redirect_uris     VARCHAR(1000) DEFAULT NULL COMMENT '登出后重定向地址 (逗号分隔)',
    scopes                        VARCHAR(1000) NOT NULL COMMENT '授权范围: openid,profile,email,read,write',
    client_settings               VARCHAR(2000) NOT NULL COMMENT '客户端设置 JSON: requireProofKey,requireAuthorizationConsent',
    token_settings                VARCHAR(2000) NOT NULL COMMENT '令牌设置 JSON: accessTokenFormat(REFERENCE/SELF_CONTAINED),accessTokenTimeToLive,reuseRefreshTokens,idTokenSignatureAlgorithm',
    INDEX idx_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='OAuth2 客户端注册表';


-- ------------------------------------------------------------
-- 3. OAuth2 授权确认表 (用户同意授权记录)
--    参考 Spring Authorization Server 官方 JdbcOAuth2AuthorizationConsentService
-- ------------------------------------------------------------
DROP TABLE IF EXISTS oauth2_authorization_consent;
CREATE TABLE oauth2_authorization_consent (
    registered_client_id VARCHAR(100)  NOT NULL COMMENT '客户端ID (关联 oauth2_registered_client.id)',
    principal_name       VARCHAR(200)  NOT NULL COMMENT '用户名 (主体标识)',
    authorities          VARCHAR(2000) NOT NULL COMMENT '授予的权限列表 (逗号分隔的 scope, 如 openid,profile)',
    first_grant_time     DATETIME      DEFAULT NULL COMMENT '首次授权时间 (只在 insert 时写入, 后续 authorities 更新不改动)',
    PRIMARY KEY (registered_client_id, principal_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='OAuth2 授权确认表 (用户对客户端的授权同意)';


-- ------------------------------------------------------------
-- 4. OAuth2 授权记录表 (授权日志)
--    记录谁、在什么时间、向哪个客户端、授予了什么权限
--    与 oauth2_authorization_consent 不同, 本表保留历史记录 (含已撤销)
-- ------------------------------------------------------------
DROP TABLE IF EXISTS oauth2_authorization_record;
CREATE TABLE oauth2_authorization_record (
    id                   BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT '主键ID',
    registered_client_id VARCHAR(100)  NOT NULL COMMENT '客户端ID (关联 oauth2_registered_client.id)',
    client_name          VARCHAR(200)  DEFAULT NULL COMMENT '客户端名称 (冗余字段, 方便查询展示)',
    principal_name       VARCHAR(200)  NOT NULL COMMENT '用户名 (授权主体)',
    granted_authorities  VARCHAR(2000) NOT NULL COMMENT '授予的权限 (scope 列表, 逗号分隔)',
    grant_time           DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '授权时间',
    revoke_time          DATETIME      DEFAULT NULL COMMENT '撤销时间 (status=revoked 时有值)',
    status               VARCHAR(20)   NOT NULL DEFAULT 'active' COMMENT '状态: active=有效, revoked=已撤销',
    grant_type           VARCHAR(100)  DEFAULT NULL COMMENT '授权类型: authorization_code / urn:ietf:params:oauth:grant-type:device_code / password 等',
    INDEX idx_principal (principal_name),
    INDEX idx_client (registered_client_id),
    INDEX idx_status (status),
    INDEX idx_grant_type (grant_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='OAuth2 授权记录表 (授权历史日志)';


-- 说明: OAuth2 运行时状态 (authorization_code / access_token / refresh_token / device_code)
--       全部存储在 Redis 中 (oauth2:auth:* 前缀), 由 Redis TTL 自动清理过期数据,
--       故无需在 MySQL 中建 oauth2_authorization 表。
--       access_token 采用 Opaque 短码格式, 撤销 (强制下线/退出) 时直接删除 Redis 中的
--       oauth2:auth:access:<token> 等索引键, 资源服务器 introspect 查不到即返回 401,
--       无需维护 JWT 黑名单。


-- ============================================================
-- 初始化数据
-- ============================================================

-- 密码: 123456  (BCrypt 加密, spring-security-crypto 6.4.4 生成)
INSERT INTO sys_user (username, password, nickname, email, role, enabled)
VALUES ('admin', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '管理员', 'admin@example.com', 'ROLE_ADMIN', 1);

INSERT INTO sys_user (username, password, nickname, email, enabled)
VALUES ('user', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '普通用户', 'user@example.com', 1);


-- 客户端: web-app (授权码模式, Confidential Client)
-- 典型场景: 传统Web应用 (服务端渲染/SSR), 有 client_secret, 通过 authorization_code + PKCE 完成用户授权
INSERT INTO oauth2_registered_client (
    id, client_id, client_secret, client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris, post_logout_redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    '1',
    'web-app',
    '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e',
    'Web 应用客户端',
    'client_secret_basic,client_secret_post',
    'authorization_code,refresh_token,password',
    'http://localhost:8080/callback,http://127.0.0.1:8080/callback',
    'http://localhost:8080/logout',
    'openid,profile,email,read,write',
    '{"requireProofKey":false,"requireAuthorizationConsent":true}',
    '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"idTokenSignatureAlgorithm":"RS256"}'
);


-- 客户端: device-app (设备码授权模式, Public Client 无密钥)
-- 典型场景: 输入受限设备 (智能电视/IoT终端/CLI工具), 无 client_secret, 通过 user_code 完成用户授权
INSERT INTO oauth2_registered_client (
    id, client_id, client_secret, client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris, post_logout_redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    '2',
    'device-app',
    NULL,
    '设备码客户端',
    'none',
    'refresh_token,urn:ietf:params:oauth:grant-type:device_code',
    NULL,
    NULL,
    'openid,profile,email,read',
    '{"requireProofKey":false,"requireAuthorizationConsent":false}',
    '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT1H","reuseRefreshTokens":false}'
);


-- 客户端: mobile-app (Public Client + 强制 PKCE)
-- 典型场景: 原生移动应用 (iOS/Android) 或 无后端纯前端项目 (SPA, 如 Vue/React/Angular)
--   两类场景协议层配置完全一致: 均为 Public Client, 无 client_secret, 必须使用 PKCE 防止授权码拦截
--   差异仅在 redirect_uri 形式:
--     - 原生 App: 自定义 scheme (com.example.mobileapp://...), 由操作系统拦截唤起 App (RFC 8252)
--     - SPA:      https URL (http://localhost:8082/callback), 由浏览器直接加载回调页
INSERT INTO oauth2_registered_client (
    id, client_id, client_secret, client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris, post_logout_redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    '3',
    'mobile-app',
    NULL,
    '移动应用客户端',
    'none',
    'authorization_code,refresh_token',
    'com.example.mobileapp://oauth2/redirect,http://localhost:8082/callback',
    'http://localhost:8082/logout',
    'openid,profile,email,read,write',
    '{"requireProofKey":true,"requireAuthorizationConsent":true}',
    '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"idTokenSignatureAlgorithm":"RS256"}'
);

-- 客户端: service-app (客户端模式, 服务间调用)
-- 典型场景: 后端服务对服务调用 (M2M), 无用户参与, 用 client_credentials 直接获取 access_token
INSERT INTO oauth2_registered_client (
    id, client_id, client_secret, client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    '4',
    'service-app',
    '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e',
    '服务间调用客户端',
    'client_secret_basic',
    'client_credentials',
    NULL,
    'read,write',
    '{"requireProofKey":false,"requireAuthorizationConsent":false}',
    '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}'
);