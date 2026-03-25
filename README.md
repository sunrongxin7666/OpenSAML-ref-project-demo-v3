# OpenSAML-ref-project-demo-v3

基于 OpenSAML 3.x 的 SAML 2.0 完整演示项目，已改造为 **Spring Boot 微服务架构**，包含独立运行的 IDP 和 SP 两个服务。

项目地址：https://github.com/sunrongxin7666/OpenSAML-ref-project-demo-v3.git
  
原始项目来源：https://bitbucket.org/srasmusson/webprofile-ref-project-v3

---

## 技术栈

| 项目 | 版本 |
|------|------|
| Java | 1.8 |
| Spring Boot | 2.7.18 |
| OpenSAML | 3.2.0 |
| 模板引擎 | Thymeleaf |
| 构建工具 | Maven 多模块 |

---

## 项目结构

```
OpenSAML-ref-project-demo-v3/
├── pom.xml                              # 父 POM（管理公共依赖）
├── saml-common/                         # 公共模块
│   └── src/main/java/no/steras/opensamlbook/
│       ├── OpenSAMLUtils.java
│       └── config/OpenSAMLConfig.java   # OpenSAML 初始化（@Configuration）
├── saml-idp/                            # IDP 微服务（端口 9090）
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
│           └── templates/login.html
└── saml-sp/                             # SP 微服务（端口 8080）
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
            └── idp-certificate.crt      # IDP 公钥（用于验签）
```

---

## 快速开始

### 环境要求

- Java 1.8+
- Maven 3.3+

### 构建

```bash
mvn clean install -DskipTests
```

### 启动

```bash
# 终端 1：启动 IDP（端口 9090）
cd saml-idp && mvn spring-boot:run

# 终端 2：启动 SP（端口 8080）
cd saml-sp && mvn spring-boot:run
```

### 访问

启动成功后，浏览器访问：

```
http://localhost:8080/app/appservlet
```

首次访问将自动跳转到 IDP 登录页，点击 **Authenticate** 按钮完成认证，随后重定向回 SP 受保护资源。

---

## SAML 认证流程

```
1. 浏览器访问 /app/appservlet
   → SamlAccessFilter 拦截，用户未认证
   → 构建 AuthnRequest，签名后重定向到 IDP

2. 浏览器跳转到 /idp/singleSignOnService?SAMLRequest=...
   → IDP 显示登录页（Authenticate 按钮）

3. 点击 Authenticate
   → IDP 重定向携带 Artifact → /sp/consumer?SAMLart=...

4. SP 处理 Artifact
   → 通过 SOAP 向 IDP 发送 ArtifactResolve
   → IDP 返回含签名+加密 Assertion 的 ArtifactResponse
   → SP 解密 Assertion，验证签名，设置 Session 为已认证
   → 重定向回原始目标 URL

5. 再次访问 /app/appservlet
   → Filter 检查 Session 已认证，放行
   → 显示受保护资源内容
```

---

## 服务端点

| 端点 | 服务 | 说明 |
|------|------|------|
| `http://localhost:8080/app/appservlet` | SP | 受保护资源（触发 SAML 认证） |
| `http://localhost:8080/sp/consumer` | SP | SAML Artifact 消费端点 |
| `http://localhost:9090/idp/singleSignOnService` | IDP | SSO 端点 |
| `http://localhost:9090/idp/artifactResolutionService` | IDP | Artifact 解析端点（SOAP） |

---

## 配置说明

### SP（saml-sp/src/main/resources/application.yml）

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

### IDP（saml-idp/src/main/resources/application.yml）

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

---

## 密钥管理

IDP 和 SP 各自持有独立的密钥库，通过交换公钥证书实现跨服务的签名验证和断言加密：

- `IDPKeystore.jks`：IDP 签名密钥库（RSA-2048）
- `idp-certificate.crt`：IDP 公钥，放入 SP 资源目录，用于验证断言签名
- `SPKeystore.jks`：SP 密钥库
- `sp-certificate.crt`：SP 公钥，放入 IDP 资源目录，用于加密断言

---

## 常见问题

### Java 1.8 SSL 证书过旧导致 Maven 下载失败

Java 1.8.0_40 的 CA 证书库过旧，无法通过 HTTPS 访问 Maven 仓库。解决方案：

```bash
cp $JAVA_HOME/jre/lib/security/cacerts /tmp/custom-cacerts
curl -sSL -o /tmp/isrg-root-x1.pem https://letsencrypt.org/certs/isrgrootx1.pem
keytool -importcert -alias isrgrootx1 -file /tmp/isrg-root-x1.pem \
  -keystore /tmp/custom-cacerts -storepass changeit -noprompt

export MAVEN_OPTS="-Djavax.net.ssl.trustStore=/tmp/custom-cacerts -Djavax.net.ssl.trustStorePassword=changeit"
```

### 系统代理导致 SOAP 调用失败

若本机配置了 HTTP 代理，Java HttpClient 会将 SP 到 IDP 的 SOAP 请求路由到代理，导致 artifact resolution 返回 404。`SpApplication.java` 已通过 JVM 属性禁用 localhost 代理：

```java
System.setProperty("http.nonProxyHosts", "localhost|127.0.0.1");
System.setProperty("java.net.useSystemProxies", "false");
```

---

## 相关文章
1. [SAML2.0入门指南](http://www.jianshu.com/p/636c1ee16eba)
2. [OpenSAML 使用引导 I : 简介](http://www.jianshu.com/p/d041935641b4)
3. [OpenSAML 使用引导 II : Service Provider 的实现之AuthnRequest](http://www.jianshu.com/p/6f61fa7be0b6)
4. [OpenSAML 使用引导 III: Service Provider 的实现之Artifact与断言](https://www.jianshu.com/p/6c72408fa480)
5. [OpenSAML 使用引导IV: 安全特性](http://www.jianshu.com/p/77bbc9758831)
