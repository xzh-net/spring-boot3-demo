package net.xzh.iam.resource.vo;

import java.util.List;

import lombok.Data;

/**
 * 授权范围展示 VO (scope.html 只读页).
 * <p>
 * scope 行 + 内含权限码 + 引用该 scope 的客户端列表 (三面合一, 无写接口)。
 * </p>
 */
@Data
public class ScopeVO {

    private Long id;

    /** scope 码 (如 admin.full) */
    private String code;

    private String name;

    /** 能力域归属: admin/portal/third */
    private String domain;

    /** 1=启用, 0=停用 */
    private Integer status;

    private String remark;

    /** 内含权限码 (含停用码, 页面置灰) */
    private List<PermissionRef> permissions;

    /** 引用该 scope 的客户端 clientId 列表 (读 oauth2_registered_client.scopes) */
    private List<String> clientIds;

    /** 权限码引用 (字典投影) */
    @Data
    public static class PermissionRef {
        private Long id;
        private String code;
        private String name;
        private Integer status;

        public PermissionRef() {
        }

        public PermissionRef(Long id, String code, String name, Integer status) {
            this.id = id;
            this.code = code;
            this.name = name;
            this.status = status;
        }
    }
}
