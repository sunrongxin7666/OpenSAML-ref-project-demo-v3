package no.steras.opensamlbook.sp.controller;

import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.sp.filter.SamlAccessFilter;
import no.steras.opensamlbook.sp.service.SamlSpService;
import org.opensaml.saml.saml2.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class ConsumerController {
    private static final Logger logger = LoggerFactory.getLogger(ConsumerController.class);

    private final SamlSpService samlSpService;

    public ConsumerController(SamlSpService samlSpService) {
        this.samlSpService = samlSpService;
    }

    @GetMapping("/sp/consumer")
    public void consumeAssertion(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        logger.info("Artifact received");
        Artifact artifact = samlSpService.buildArtifactFromRequest(req);
        logger.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = samlSpService.buildArtifactResolve(artifact);
        logger.info("Sending ArtifactResolve");
        logger.info("ArtifactResolve: ");
        OpenSAMLUtils.logSAMLObject(artifactResolve);

        ArtifactResponse artifactResponse = samlSpService.sendAndReceiveArtifactResolve(artifactResolve);
        logger.info("ArtifactResponse received");
        logger.info("ArtifactResponse: ");
        OpenSAMLUtils.logSAMLObject(artifactResponse);

        samlSpService.validateDestinationAndLifetime(artifactResponse, req);

        EncryptedAssertion encryptedAssertion = samlSpService.getEncryptedAssertion(artifactResponse);
        Assertion assertion = samlSpService.decryptAssertion(encryptedAssertion);
        samlSpService.verifyAssertionSignature(assertion);
        logger.info("Decrypted Assertion: ");
        OpenSAMLUtils.logSAMLObject(assertion);

        samlSpService.logAssertionAttributes(assertion);
        samlSpService.logAuthenticationInstant(assertion);
        samlSpService.logAuthenticationMethod(assertion);

        req.getSession().setAttribute(SamlAccessFilter.AUTHENTICATED_SESSION_ATTRIBUTE, true);

        String gotoURL = (String) req.getSession().getAttribute(SamlAccessFilter.GOTO_URL_SESSION_ATTRIBUTE);
        if (gotoURL == null) {
            gotoURL = "/app/appservlet";
        }
        logger.info("Redirecting to requested URL: " + gotoURL);
        resp.sendRedirect(gotoURL);
    }
}
