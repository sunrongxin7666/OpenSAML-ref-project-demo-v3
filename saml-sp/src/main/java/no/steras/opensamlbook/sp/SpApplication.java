package no.steras.opensamlbook.sp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"no.steras.opensamlbook"})
public class SpApplication {
    public static void main(String[] args) {
        // Disable system proxy for localhost SOAP calls to IDP
        System.setProperty("http.nonProxyHosts", "localhost|127.0.0.1");
        System.setProperty("java.net.useSystemProxies", "false");
        SpringApplication.run(SpApplication.class, args);
    }
}
