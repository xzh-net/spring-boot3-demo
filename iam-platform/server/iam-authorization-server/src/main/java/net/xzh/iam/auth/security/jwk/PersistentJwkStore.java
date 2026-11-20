package net.xzh.iam.auth.security.jwk;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT 签名密钥的持久化存储.
 *
 * <p>首次启动时生成 RSA(2048) + EC(P-256) 密钥对并写入密钥库文件，
 * 后续启动直接复用同一份密钥。这样可保证：
 * <ul>
 *   <li>服务重启后，此前签发的 id_token 仍可用 JWKS 公钥验签；</li>
 *   <li>多实例共享同一密钥库文件（挂载共享卷）时，各实例 JWKS 输出一致。</li>
 * </ul>
 *
 * <p>密钥库文件含私钥，必须限制访问权限（POSIX 系统写入 600）。
 * 文件损坏或解析失败时直接抛出异常终止启动，避免静默轮换密钥导致存量令牌全部失效。
 */
@Slf4j
@Component
public class PersistentJwkStore {

    /** 密钥库文件路径 */
    private final Path keystorePath;

    private RSAKey rsaKey;
    private ECKey ecKey;

    public PersistentJwkStore(@Value("${iam.jwk.keystore-path:./data/jwks.json}") String keystorePath) {
        this.keystorePath = Paths.get(keystorePath).toAbsolutePath().normalize();
    }

    @PostConstruct
    void init() {
        JWKSet existing = loadIfPresent();
        if (existing == null) {
            this.rsaKey = generateRsa();
            this.ecKey = generateEc();
            save(new JWKSet(List.of(rsaKey, ecKey)));
            log.info("JWK 密钥库不存在, 已生成: path={}, rsaKid={}, ecKid={}",
                    keystorePath, rsaKey.getKeyID(), ecKey.getKeyID());
            return;
        }

        this.rsaKey = findRsa(existing);
        this.ecKey = findEc(existing);

        List<JWK> keys = new ArrayList<>(existing.getKeys());
        boolean changed = false;
        if (rsaKey == null) {
            rsaKey = generateRsa();
            keys.add(rsaKey);
            changed = true;
        }
        if (ecKey == null) {
            ecKey = generateEc();
            keys.add(ecKey);
            changed = true;
        }
        if (changed) {
            save(new JWKSet(keys));
            log.warn("JWK 密钥库缺少密钥类型, 已补齐: path={}", keystorePath);
        }
        log.info("已加载 JWK 密钥库: path={}, rsaKid={}, ecKid={}",
                keystorePath, rsaKey.getKeyID(), ecKey.getKeyID());
    }

    public RSAKey getRsaKey() {
        return rsaKey;
    }

    public ECKey getEcKey() {
        return ecKey;
    }

    private JWKSet loadIfPresent() {
        if (!Files.exists(keystorePath)) {
            return null;
        }
        try {
            return JWKSet.parse(Files.readString(keystorePath));
        } catch (IOException | ParseException e) {
            throw new IllegalStateException(
                    "JWK 密钥库读取失败, 请检查文件是否完整: " + keystorePath, e);
        }
    }

    private static RSAKey findRsa(JWKSet jwkSet) {
        return jwkSet.getKeys().stream()
                .filter(RSAKey.class::isInstance)
                .map(RSAKey.class::cast)
                .findFirst()
                .orElse(null);
    }

    private static ECKey findEc(JWKSet jwkSet) {
        return jwkSet.getKeys().stream()
                .filter(ECKey.class::isInstance)
                .map(ECKey.class::cast)
                .findFirst()
                .orElse(null);
    }

    private static RSAKey generateRsa() {
        try {
            return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        } catch (Exception e) {
            throw new IllegalStateException("生成 RSA 密钥失败", e);
        }
    }

    private static ECKey generateEc() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        } catch (Exception e) {
            throw new IllegalStateException("生成 EC 密钥失败", e);
        }
    }

    /** 先写临时文件再原子替换, 避免写一半导致密钥库损坏 */
    private void save(JWKSet jwkSet) {
        Path dir = keystorePath.getParent();
        try {
            if (dir != null) {
                Files.createDirectories(dir);
            }
            Path tmp = Files.createTempFile(dir, "jwks-", ".json.tmp");
            Files.writeString(tmp, jwkSet.toString(false));
            restrictPermissions(tmp);
            try {
                Files.move(tmp, keystorePath,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, keystorePath, StandardCopyOption.REPLACE_EXISTING);
            }
            restrictPermissions(keystorePath);
        } catch (IOException e) {
            throw new IllegalStateException("JWK 密钥库写入失败: " + keystorePath, e);
        }
    }

    /** 密钥库含私钥, POSIX 系统收紧为仅属主可读写; 非 POSIX 系统跳过 */
    private static void restrictPermissions(Path path) {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        try {
            Files.setPosixFilePermissions(path, ownerOnly);
        } catch (UnsupportedOperationException ignored) {
            // Windows 等非 POSIX 文件系统, 跳过
        } catch (IOException e) {
            log.warn("设置 JWK 密钥库权限失败, 请人工确认文件访问权限: {}", path);
        }
    }
}
