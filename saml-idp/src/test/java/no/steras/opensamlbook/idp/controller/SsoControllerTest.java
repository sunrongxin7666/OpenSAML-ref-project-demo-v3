package no.steras.opensamlbook.idp.controller;

import no.steras.opensamlbook.idp.config.IDPProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class SsoControllerTest {

    private SsoController ssoController;
    private IDPProperties idpProperties;

    @BeforeEach
    void setUp() {
        idpProperties = new IDPProperties();
        IDPProperties.Sp sp = new IDPProperties.Sp();
        sp.setAssertionConsumerService("https://sp.example.com/consumer");
        idpProperties.setSp(sp);
        ssoController = new SsoController(idpProperties);
    }

    @Test
    void showLoginPage_shouldReturnLoginViewName() {
        String viewName = ssoController.showLoginPage();
        assertThat(viewName).isEqualTo("login");
    }

    @Test
    void authenticate_shouldRedirectToSpConsumerService() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        ssoController.authenticate(response);

        assertThat(response.getRedirectedUrl()).startsWith("https://sp.example.com/consumer");
        assertThat(response.getRedirectedUrl()).contains("SAMLart=");
    }

    @Test
    void authenticate_shouldIncludeSAMLartParameter() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        ssoController.authenticate(response);

        String redirectUrl = response.getRedirectedUrl();
        assertThat(redirectUrl).contains("SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D");
    }
}
