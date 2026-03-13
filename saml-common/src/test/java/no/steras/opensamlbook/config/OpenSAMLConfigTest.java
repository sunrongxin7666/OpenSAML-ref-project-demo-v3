package no.steras.opensamlbook.config;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;

import static org.assertj.core.api.Assertions.assertThat;

class OpenSAMLConfigTest {

    @Test
    void init_OpenSAML初始化成功() {
        OpenSAMLConfig config = new OpenSAMLConfig();
        config.init();

        assertThat(XMLObjectProviderRegistrySupport.getBuilderFactory()).isNotNull();
        assertThat(XMLObjectProviderRegistrySupport.getMarshallerFactory()).isNotNull();
        assertThat(XMLObjectProviderRegistrySupport.getUnmarshallerFactory()).isNotNull();
    }
}
