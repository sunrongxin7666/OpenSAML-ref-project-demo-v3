package no.steras.opensamlbook;

import no.steras.opensamlbook.config.OpenSAMLConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OpenSAMLUtilsTest {

    @BeforeAll
    static void initOpenSAML() {
        new OpenSAMLConfig().init();
    }

    @Test
    void buildSAMLObject_成功构建AuthnRequest() {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        assertThat(authnRequest).isNotNull();
    }

    @Test
    void buildSAMLObject_无效类抛异常() {
        assertThatThrownBy(() -> OpenSAMLUtils.buildSAMLObject(String.class))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void generateSecureRandomId_生成唯一ID() {
        String id1 = OpenSAMLUtils.generateSecureRandomId();
        String id2 = OpenSAMLUtils.generateSecureRandomId();

        assertThat(id1).isNotNull().isNotEmpty();
        assertThat(id2).isNotNull().isNotEmpty();
        assertThat(id1).isNotEqualTo(id2);
    }

    @Test
    void logSAMLObject_不抛异常() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue("TestIssuer");

        // Should not throw any exception
        OpenSAMLUtils.logSAMLObject(issuer);
    }
}
