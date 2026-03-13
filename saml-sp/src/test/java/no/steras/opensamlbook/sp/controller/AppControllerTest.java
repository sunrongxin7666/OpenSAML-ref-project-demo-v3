package no.steras.opensamlbook.sp.controller;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AppControllerTest {

    @Test
    void protectedResource_shouldReturnHtmlContent() {
        AppController controller = new AppController();

        String result = controller.protectedResource();

        assertThat(result).isNotNull();
        assertThat(result).contains("You are now at the requested resource");
        assertThat(result).contains("authenticated");
    }

    @Test
    void protectedResource_shouldContainH1Tag() {
        AppController controller = new AppController();

        String result = controller.protectedResource();

        assertThat(result).contains("<h1>");
        assertThat(result).contains("</h1>");
    }
}
