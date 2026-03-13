package no.steras.opensamlbook.idp.controller;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.idp.config.IDPProperties;
import no.steras.opensamlbook.idp.service.SamlIdpService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

@Controller
public class ArtifactResolutionController {
    private static final Logger logger = LoggerFactory.getLogger(ArtifactResolutionController.class);

    private final SamlIdpService samlIdpService;
    private final ResourceLoader resourceLoader;
    private Credential spEncryptionCredential;

    public ArtifactResolutionController(SamlIdpService samlIdpService,
                                        IDPProperties idpProperties,
                                        ResourceLoader resourceLoader) {
        this.samlIdpService = samlIdpService;
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        try {
            Resource resource = resourceLoader.getResource("classpath:sp-certificate.crt");
            InputStream inputStream = resource.getInputStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(inputStream);
            inputStream.close();

            spEncryptionCredential = CredentialSupport.getSimpleCredential(cert.getPublicKey(), null);
            logger.info("SP encryption credential loaded from certificate");
        } catch (Exception e) {
            throw new RuntimeException("Failed to load SP encryption credential", e);
        }
    }

    @PostMapping("/idp/artifactResolutionService")
    public void resolveArtifact(HttpServletRequest req, HttpServletResponse resp) {
        logger.debug("Received artifactResolve");

        HTTPSOAP11Decoder decoder = new HTTPSOAP11Decoder();
        decoder.setHttpServletRequest(req);

        try {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();
            decoder.setParserPool(parserPool);
            decoder.initialize();
            decoder.decode();
        } catch (MessageDecodingException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        OpenSAMLUtils.logSAMLObject(decoder.getMessageContext().getMessage());

        ArtifactResponse artifactResponse = samlIdpService.buildArtifactResponse(spEncryptionCredential);

        MessageContext<SAMLObject> context = new MessageContext<SAMLObject>();
        context.setMessage(artifactResponse);

        HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(resp);

        try {
            encoder.prepareContext();
            encoder.initialize();
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }
    }
}
