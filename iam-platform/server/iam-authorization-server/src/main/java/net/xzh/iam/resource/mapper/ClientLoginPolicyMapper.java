package net.xzh.iam.resource.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.iam.resource.entity.ClientLoginPolicy;

/**
 * client_login_policy Mapper (登录准入表)。
 * <p>
 * 当前仅只读查询 (供 {@code LoginAdmissionService.canLogin} 判定);
 * 管理 API / 页面的写入口待评估后补。
 * </p>
 */
public interface ClientLoginPolicyMapper extends BaseMapper<ClientLoginPolicy> {
}
