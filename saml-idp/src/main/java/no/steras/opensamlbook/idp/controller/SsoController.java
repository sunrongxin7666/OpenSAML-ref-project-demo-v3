package no.steras.opensamlbook.idp.controller;

import no.steras.opensamlbook.idp.config.IDPProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class SsoController {
    private static final Logger logger = LoggerFactory.getLogger(SsoController.class);

    private final IDPProperties idpProperties;

    public SsoController(IDPProperties idpProperties) {
        this.idpProperties = idpProperties;
    }

    @GetMapping("/idp/singleSignOnService")
    public String showLoginPage() {
        logger.info("AuthnRequest received");
        return "login";
    }

    @PostMapping("/idp/singleSignOnService")
    public void authenticate(HttpServletResponse resp) throws IOException {
        String redirectUrl = idpProperties.getSp().getAssertionConsumerService()
                + "?SAMLart=AAQAAMFbLinlXaCM%2BFIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg%3D";
        resp.sendRedirect(redirectUrl);
    }
}
