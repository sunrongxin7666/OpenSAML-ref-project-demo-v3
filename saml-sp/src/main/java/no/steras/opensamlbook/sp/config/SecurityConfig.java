package no.steras.opensamlbook.sp.config;

import no.steras.opensamlbook.sp.filter.SamlAccessFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

    @Bean
    public FilterRegistrationBean<SamlAccessFilter> samlAccessFilterRegistration(SamlAccessFilter filter) {
        FilterRegistrationBean<SamlAccessFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/app/*");
        registration.setOrder(1);
        return registration;
    }
}
