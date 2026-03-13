package no.steras.opensamlbook.sp.config;

import no.steras.opensamlbook.sp.filter.SamlAccessFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityConfigTest {

    @Test
    void samlAccessFilterRegistration_shouldRegisterFilterForAppPath() {
        SecurityConfig config = new SecurityConfig();
        SamlAccessFilter filter = mock(SamlAccessFilter.class);

        FilterRegistrationBean<SamlAccessFilter> registration = config.samlAccessFilterRegistration(filter);

        assertThat(registration).isNotNull();
        assertThat(registration.getFilter()).isEqualTo(filter);
        assertThat(registration.getUrlPatterns()).contains("/app/*");
        assertThat(registration.getOrder()).isEqualTo(1);
    }
}
