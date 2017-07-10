#OpenSAML-ref-project-demo-v3
这一个使用OpenSAML库的示例项目：
一个很简单的网址，其充当SP；同时该项目还包括一个很简单的IDP；
SAML协议的交互将在这二者之间展开。

项目地址：
https://github.com/sunrongxin7666/OpenSAML-ref-project-demo-v3.git

这个项目基于Bitbucket的一个实验项目https://bitbucket.org/srasmusson/webprofile-ref-project-v3
其本身是使用Apache Maveng构建的，启动项目需要执行

```
mvn tomcat:run
```
嵌入项目中的Tomcat就会启动，运行成功时会有如下信息：
>INFO: Starting Coyote HTTP/1.1 on http-8080

经过本人的修改，该项目可以在**IntelliJ Idea**以工程模式打开，运行方式设置为mvn，命令是tomcat:run。这就便于读者调试和修改。

项目启动之后，访问如下网址：
http://localhost:8080/webprofile-ref-project/app/appservlet
这是一个SP的模拟，第一次访问该网址时将会跳转到IDP，进行认证流程。
![IDP](https://github.com/sunrongxin7666/OpenSAML-ref-project-demo-v3/blob/master/shortcut/1499671904812.png)

点击“Authenticate”按钮将通过认证，并重定向回SP,
![SP](https://github.com/sunrongxin7666/OpenSAML-ref-project-demo-v3/blob/master/shortcut/1499672009116.png)

到此为止整个SAML协议的流程及完成了，相关日志信息会在控制台中输出。