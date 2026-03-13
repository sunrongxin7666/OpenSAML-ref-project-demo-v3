# OpenSAML 项目 Spring Boot 微服务改造文档

## 1. 改造背景

原项目是一个基于传统 Servlet 的 OpenSAML 3.2.0 SAML 2.0 演示项目，SP 和 IDP 在同一个 WAR 中运行。改造目标是将其拆分为两个独立的 Spring Boot 微服务，同时保持 OpenSAML 3.x 版本不变。

## 2. 技术选型

| 项目 | 选型 |
|------|------|
| Spring Boot | 2.7.18（兼容 Java 8 和 OpenSAML 3.x） |
| OpenSAML | 3.2.0（保持不变） |
| 模板引擎 | Thymeleaf |
| 构建工具 | Maven 多模块 |
| Java | 1.8 |

## 3. 项目结构

### 改造前

```
OpenSAML-ref-project-demo-v3/
├── pom.xml                          # 单体 WAR
├── src/main/java/no/steras/opensamlbook/
│   ├── OpenSAMLUtils.java
│   ├── app/ApplicationServlet.java
│   ├── idp/
│   │   ├── IDPConstants.java
│   │   ├── IDPCredentials.java       # 运行时生成 RSA 密钥对
│   │   ├── SingleSignOnServlet.java
│   │   └── ArtifactResolutionServlet.java
│   └── sp/
│       ├── SPConstants.java
│       ├── SPCredentials.java
│       ├── AccessFilter.java         # 含 OpenSAML 初始化逻辑
│       └── ConsumerServlet.java
├── src/main/resources/SPKeystore.jks
└── src/main/webapp/WEB-INF/web.xml
```

### 改造后

```
OpenSAML-ref-project-demo-v3/
├── pom.xml                              # 父 POM（管理公共依赖）
├── saml-common/                         # 公共模块
│   ├── pom.xml
│   └── src/main/java/no/steras/opensamlbook/
│       ├── OpenSAMLUtils.java
│       └── config/OpenSAMLConfig.java   # OpenSAML 初始化（@Configuration）
├── saml-idp/                            # IDP 微服务（端口 9090）
│   ├── pom.xml
│   └── src/main/
│       ├── java/no/steras/opensamlbook/idp/
│       │   ├── IdpApplication.java
│       │   ├── config/IDPProperties.java
│       │   ├── credential/IDPCredentials.java
│       │   ├── controller/
│       │   │   ├── SsoController.java
│       │   │   └── ArtifactResolutionController.java
│       │   └── service/SamlIdpService.java
│       └── resources/
│           ├── application.yml
│           ├── IDPKeystore.jks          # IDP 签名密钥库
│           ├── sp-certificate.crt       # SP 公钥（用于加密断言）
│           ├── logback.xml
│           └── templates/login.html
└── saml-sp/                             # SP 微服务（端口 8080）
    ├── pom.xml
    └── src/main/
        ├── java/no/steras/opensamlbook/sp/
        │   ├── SpApplication.java
        │   ├── config/
        │   │   ├── SPProperties.java
        │   │   └── SecurityConfig.java
        │   ├── credential/SPCredentials.java
        │   ├── filter/SamlAccessFilter.java
        │   ├── controller/
        │   │   ├── ConsumerController.java
        │   │   └── AppController.java
        │   └── service/SamlSpService.java
        └── resources/
            ├── application.yml
            ├── SPKeystore.jks
            ├── idp-certificate.crt      # IDP 公钥（用于验签）
            └── logback.xml
```

## 4. 核心改动项

### 4.1 父 POM

- 打包方式从 `war` 改为 `pom`
- 通过 `spring-boot-dependencies` BOM 管理 Spring Boot 版本
- 统一管理 OpenSAML 3.2.0 依赖版本
- 子模块：`saml-common`、`saml-idp`、`saml-sp`

### 4.2 saml-common 模块

| 文件 | 说明 |
|------|------|
| `OpenSAMLUtils.java` | 从原项目原样迁移 |
| `OpenSAMLConfig.java` | **新增**，将 `AccessFilter.init()` 中的 OpenSAML 初始化逻辑提取为 `@Configuration` + `@PostConstruct`，两个服务自动执行初始化 |

### 4.3 saml-idp 模块（端口 9090）

| 原始类 | 改造后 | 改动说明 |
|--------|--------|----------|
| `SingleSignOnServlet` | `SsoController` | `@GetMapping` 返回 Thymeleaf `login.html`；`@PostMapping` 重定向携带 Artifact |
| `ArtifactResolutionServlet` | `ArtifactResolutionController` | `@PostMapping` 处理 SOAP ArtifactResolve 请求 |
| `IDPConstants` | `IDPProperties` | `@ConfigurationProperties(prefix="saml.idp")`，配置外部化到 `application.yml` |
| `IDPCredentials` | `IDPCredentials`（@Component） | **重大变更**：从运行时生成 RSA 密钥对改为从固定 KeyStore（`IDPKeystore.jks`）加载 |
| — | `SamlIdpService` | **新增**，提取断言构建、签名、加密等核心逻辑 |
| — | `login.html` | **新增**，Thymeleaf 模板替代 Servlet 中的 HTML 字符串 |

### 4.4 saml-sp 模块（端口 8080）

| 原始类 | 改造后 | 改动说明 |
|--------|--------|----------|
| `AccessFilter` | `SamlAccessFilter` | 继承 `OncePerRequestFilter`，注册为 Spring Filter Bean，拦截 `/app/*` |
| `ConsumerServlet` | `ConsumerController` | `@GetMapping("/sp/consumer")`，委托 `SamlSpService` 处理 |
| `ApplicationServlet` | `AppController` | `@GetMapping("/app/appservlet")` + `@ResponseBody` |
| `SPConstants` | `SPProperties` | `@ConfigurationProperties(prefix="saml.sp")`，配置外部化 |
| `SPCredentials` | `SPCredentials`（@Component） | 从 `@Value` 注入路径和密码；新增加载 IDP 公钥证书用于验签 |
| — | `SamlSpService` | **新增**，提取 AuthnRequest 构建、ArtifactResolve 发送、断言解密和验签等核心逻辑 |
| — | `SecurityConfig` | **新增**，通过 `FilterRegistrationBean` 注册 SAML 过滤器 |

### 4.5 密钥管理改造

改造前 IDP 在运行时随机生成 RSA 密钥对，SP 因在同一 JVM 中可直接引用。拆分后需要固定密钥：

1. **生成 IDP 密钥库**：`keytool -genkeypair` 生成 `IDPKeystore.jks`（RSA-2048）
2. **导出 IDP 公钥证书**：导出 `idp-certificate.crt` 放入 SP 资源目录，用于验证断言签名
3. **导出 SP 公钥证书**：导出 `sp-certificate.crt` 放入 IDP 资源目录，用于加密断言

### 4.6 URL 路径调整

| 端点 | 改造前 | 改造后 |
|------|--------|--------|
| SP 受保护资源 | `/webprofile-ref-project/app/appservlet` | `/app/appservlet` |
| SP Consumer | `/webprofile-ref-project/sp/consumer` | `/sp/consumer` |
| IDP SSO | `/webprofile-ref-project/idp/singleSignOnService` | `/idp/singleSignOnService` |
| IDP Artifact Resolution | `/webprofile-ref-project/idp/artifactResolutionService` | `/idp/artifactResolutionService` |

### 4.7 配置外部化

**saml-sp `application.yml`：**

```yaml
server:
  port: 8080
saml:
  sp:
    entity-id: TestSP
    assertion-consumer-service: http://localhost:8080/sp/consumer
    keystore-path: classpath:SPKeystore.jks
    keystore-password: password
    key-alias: SPKey
    key-password: password
    idp-certificate-path: classpath:idp-certificate.crt
    idp:
      sso-service: http://localhost:9090/idp/singleSignOnService
      artifact-resolution-service: http://localhost:9090/idp/artifactResolutionService
```

**saml-idp `application.yml`：**

```yaml
server:
  port: 9090
saml:
  idp:
    entity-id: TestIDP
    sso-service: http://localhost:9090/idp/singleSignOnService
    artifact-resolution-service: http://localhost:9090/idp/artifactResolutionService
    keystore-path: classpath:IDPKeystore.jks
    keystore-password: password
    key-alias: IDPKey
    key-password: password
    sp:
      assertion-consumer-service: http://localhost:8080/sp/consumer
      entity-id: TestSP
```

## 5. 构建与运行

### 5.1 环境要求

- Java 1.8+
- Maven 3.3+

### 5.2 已知问题：Java 1.8.0_40 SSL 证书

Java 1.8.0_40 的 CA 证书库过旧，无法通过 HTTPS 访问 Maven 仓库。解决方案：

```bash
# 创建自定义信任库，导入新版 CA 证书
cp $JAVA_HOME/jre/lib/security/cacerts /tmp/custom-cacerts
curl -sSL -o /tmp/isrg-root-x1.pem https://letsencrypt.org/certs/isrgrootx1.pem
keytool -importcert -alias isrgrootx1 -file /tmp/isrg-root-x1.pem \
  -keystore /tmp/custom-cacerts -storepass changeit -noprompt

# 后续 Maven 命令需携带此参数
export MAVEN_OPTS="-Djavax.net.ssl.trustStore=/tmp/custom-cacerts -Djavax.net.ssl.trustStorePassword=changeit"
```

### 5.3 构建

```bash
mvn clean install -DskipTests
```

### 5.4 启动

```bash
# 终端 1：启动 IDP（端口 9090）
cd saml-idp && mvn spring-boot:run

# 终端 2：启动 SP（端口 8080）
cd saml-sp && mvn spring-boot:run
```

## 6. 验证过程

### 6.1 编译验证

```
[INFO] opensaml-ref-project ............................... SUCCESS
[INFO] saml-common ........................................ SUCCESS  (2 source files)
[INFO] saml-idp ........................................... SUCCESS  (6 source files)
[INFO] saml-sp ............................................ SUCCESS  (8 source files)
[INFO] BUILD SUCCESS
```

### 6.2 启动验证

**IDP 启动日志（关键信息）：**

```
IdpApplication    - Starting IdpApplication using Java 1.8.0_40
IDPCredentials    - IDP credentials loaded from keystore
ArtifactResolutionController - SP encryption credential loaded from certificate
OpenSAMLConfig    - Initializing OpenSAML
TomcatWebServer   - Tomcat started on port(s): 9090 (http)
IdpApplication    - Started IdpApplication in 1.943 seconds
```

**SP 启动日志（关键信息）：**

```
SpApplication     - Starting SpApplication using Java 1.8.0_40
SPCredentials     - SP credentials loaded from keystore
SPCredentials     - IDP verification credential loaded from certificate
OpenSAMLConfig    - Initializing OpenSAML
TomcatWebServer   - Tomcat started on port(s): 8080 (http)
SpApplication     - Started SpApplication in 1.638 seconds
```

### 6.3 SAML 流程验证

浏览器访问 `http://localhost:8080/app/appservlet`，完整流程如下：

```
1. [浏览器] GET /app/appservlet
   → SamlAccessFilter 拦截，用户未认证
   → 保存目标 URL 到 Session
   → 构建 AuthnRequest，签名后重定向到 IDP

2. [浏览器] GET /idp/singleSignOnService?SAMLRequest=...
   → IDP 显示 Thymeleaf 登录页（Authenticate 按钮）

3. [浏览器] POST /idp/singleSignOnService
   → IDP 重定向：302 → /sp/consumer?SAMLart=...

4. [浏览器] GET /sp/consumer?SAMLart=...
   → SP 构建 ArtifactResolve
   → SP 通过 SOAP 发送到 IDP 的 /idp/artifactResolutionService
   → IDP 构建 ArtifactResponse（含签名+加密的 Assertion）
   → SP 解密 Assertion，验证签名
   → 设置 Session 为已认证
   → 重定向到原始目标 URL

5. [浏览器] GET /app/appservlet
   → SamlAccessFilter 检查 Session，已认证，放行
   → 显示 "You are now at the requested resource"
```

**SP 控制台输出（关键日志）：**

```
ConsumerController  - Artifact received
SamlSpService       - SAML Assertion signature verified
SamlSpService       - Attribute name: username
SamlSpService       - Attribute value: bob
SamlSpService       - Attribute name: telephone
SamlSpService       - Attribute value: 999999999
SamlSpService       - Authentication instant: 2026-03-12T10:00:12.718Z
SamlSpService       - Authentication method: urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard
ConsumerController  - Redirecting to requested URL: http://localhost:8080/app/appservlet
```

### 6.4 验证结果

| 验证项 | 结果 |
|--------|------|
| IDP 启动（端口 9090） | 通过 |
| SP 启动（端口 8080） | 通过 |
| 访问受保护资源触发 SAML 认证 | 通过 |
| 重定向到 IDP 登录页 | 通过 |
| 点击 Authenticate 携带 Artifact 跳回 SP | 通过 |
| SP 通过 SOAP 向 IDP 解析 Artifact | 通过 |
| 断言解密成功 | 通过 |
| 断言签名验证通过 | 通过 |
| 用户属性正确（username=bob, telephone=999999999） | 通过 |
| 认证后访问受保护资源成功 | 通过 |

## 7. 遇到的问题与解决

### 7.1 Java SSL 证书过期

**问题**：Java 1.8.0_40 的 CA 证书库过旧，Maven 无法从 HTTPS 仓库下载依赖。

**解决**：创建自定义信任库，导入 ISRG Root X1（Let's Encrypt）和 DigiCert Global Root G2 证书，通过 `MAVEN_OPTS` 指定。

### 7.2 系统代理导致 SOAP 调用失败

**问题**：系统配置了 HTTP 代理（127.0.0.1:7890），Java HttpClient 使用系统代理发送 SOAP 请求，导致 SP 调用 IDP 的 artifact resolution 端点返回 404。

**解决**：在 `SpApplication.main()` 中设置 JVM 属性禁用 localhost 代理：

```java
System.setProperty("http.nonProxyHosts", "localhost|127.0.0.1");
System.setProperty("java.net.useSystemProxies", "false");
```
