package no.steras.opensamlbook.sp.filter;

import no.steras.opensamlbook.config.OpenSAMLConfig;
import no.steras.opensamlbook.sp.config.SPProperties;
import no.steras.opensamlbook.sp.credential.SPCredentials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.security.credential.Credential;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SamlAccessFilterTest {

    private SamlAccessFilter filter;
    private SPProperties spProperties;
    private SPCredentials spCredentials;

    @BeforeAll
    static void initOpenSAML() {
        new OpenSAMLConfig().init();
    }

    @BeforeEach
    void setUp() {
        spProperties = new SPProperties();
        spProperties.setEntityId("https://sp.example.com");
        spProperties.setAssertionConsumerService("https://sp.example.com/consumer");
        SPProperties.Idp idp = new SPProperties.Idp();
        idp.setSsoService("https://idp.example.com/sso");
        spProperties.setIdp(idp);

        spCredentials = mock(SPCredentials.class);
        Credential mockCredential = mock(Credential.class);
        when(spCredentials.getCredential()).thenReturn(mockCredential);

        filter = new SamlAccessFilter(spProperties, spCredentials);
    }

    @Test
    void doFilterInternal_shouldPassThroughWhenAuthenticated() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(SamlAccessFilter.AUTHENTICATED_SESSION_ATTRIBUTE, true);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilterInternal(request, response, filterChain);

        // filter chain was invoked, meaning the request passed through
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    void doFilterInternal_shouldSetGotoURLWhenNotAuthenticated() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/app/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        try {
            filter.doFilterInternal(request, response, filterChain);
        } catch (RuntimeException e) {
            // encoder may throw because mock credential has no real key
        }

        String gotoUrl = (String) request.getSession().getAttribute(SamlAccessFilter.GOTO_URL_SESSION_ATTRIBUTE);
        assertThat(gotoUrl).isNotNull();
    }

    @Test
    void authenticatedSessionAttribute_shouldBeCorrectConstant() {
        assertThat(SamlAccessFilter.AUTHENTICATED_SESSION_ATTRIBUTE).isEqualTo("authenticated");
    }

    @Test
    void gotoUrlSessionAttribute_shouldBeCorrectConstant() {
        assertThat(SamlAccessFilter.GOTO_URL_SESSION_ATTRIBUTE).isEqualTo("gotoURL");
    }
}
