# Spring Authorization Server 1.5.2

- spring-security-oauth2-authorization-server已迁移至 Spring Security 7.0

- 1.5.x 分支将在 2026 年 6 月停止维护



## GitHub 第三方登录

### 集成方式选择

GitHub Apps

- **适用场景**：为自动化任务构建集成
- **典型用途**：CI/CD、代码质量、项目管理工具
- **优势特点**：更安全、更灵活，是现代 GitHub 集成的推荐方式

OAuth Apps

- **适用场景**：
  - 需要用户使用 GitHub 身份登录你的服务
  - 需要代表用户执行个人操作


### 创建应用

1. 在 GitHub 任意页面的右上角，单击你的个人资料照片，然后单击 `Settings`。

2. 在左边栏中，单击 `Developer Settings`。

3. 在左侧边栏中，单击 `OAuth Apps`。

4. 单击`New OAuth app`新建应用。

5. 在`Application name`中，输入应用程序的名称。

6. 在`Homepage URL`中，输入应用程序网站的完整 URL。

7. 在`Application description`中，输入用户将看到的应用程序说明。

8. 在`Authorization callback URL`中，输入应用程序的回调 URL。（测试地址：http://localhost:9000/login/oauth2/code/github-idp）

   > 与 GitHub Apps 不同，OAuth Apps 不能有多个回调 URL。

9. 如果 OAuth App 将使用设备流来识别和授权用户，请单击` Enable Device Flow`启用设备流。

10. 创建成功会跳转到详情页面，复制`Client ID`
11. 点击`Generate a new client secret`生成`Client secrets`



## Google 第三方登录