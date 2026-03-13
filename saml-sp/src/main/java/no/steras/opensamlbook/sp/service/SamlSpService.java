package no.steras.opensamlbook.sp.service;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.sp.config.SPProperties;
import no.steras.opensamlbook.sp.credential.SPCredentials;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Service
public class SamlSpService {
    private static final Logger logger = LoggerFactory.getLogger(SamlSpService.class);

    private final SPProperties spProperties;
    private final SPCredentials spCredentials;

    public SamlSpService(SPProperties spProperties, SPCredentials spCredentials) {
        this.spProperties = spProperties;
        this.spCredentials = spCredentials;
    }

    public Artifact buildArtifactFromRequest(HttpServletRequest req) {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact(req.getParameter("SAMLart"));
        return artifact;
    }

    public ArtifactResolve buildArtifactResolve(Artifact artifact) {
        ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(spProperties.getEntityId());
        artifactResolve.setIssuer(issuer);
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());
        artifactResolve.setDestination(spProperties.getIdp().getArtifactResolutionService());
        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }

    public ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
        try {
            MessageContext<ArtifactResolve> contextout = new MessageContext<ArtifactResolve>();
            contextout.setMessage(artifactResolve);

            SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signatureSigningParameters.setSigningCredential(spCredentials.getCredential());
            signatureSigningParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            SecurityParametersContext securityParametersContext =
                    contextout.getSubcontext(SecurityParametersContext.class, true);
            if (securityParametersContext != null) {
                securityParametersContext.setSignatureSigningParameters(signatureSigningParameters);
            }

            InOutOperationContext<ArtifactResponse, ArtifactResolve> context =
                    new ProfileRequestContext<ArtifactResponse, ArtifactResolve>();
            context.setOutboundMessageContext(contextout);

            AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject> soapClient =
                    new AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject>() {
                        @Nonnull
                        protected HttpClientMessagePipeline newPipeline() throws SOAPException {
                            HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
                            HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();
                            BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(
                                    encoder, decoder);
                            pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
                            return pipeline;
                        }
                    };

            HttpClientBuilder clientBuilder = new HttpClientBuilder();
            soapClient.setHttpClient(clientBuilder.buildClient());
            soapClient.send(spProperties.getIdp().getArtifactResolutionService(), context);

            return context.getInboundMessageContext().getMessage();
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void validateDestinationAndLifetime(ArtifactResponse artifactResponse, HttpServletRequest request) {
        MessageContext context = new MessageContext<ArtifactResponse>();
        context.setMessage(artifactResponse);

        SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
        messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());

        MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
        lifetimeSecurityHandler.setClockSkew(1000);
        lifetimeSecurityHandler.setMessageLifetime(2000);
        lifetimeSecurityHandler.setRequiredRule(true);

        ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
        receivedEndpointSecurityHandler.setHttpServletRequest(request);

        List handlers = new ArrayList<MessageHandler>();
        handlers.add(lifetimeSecurityHandler);
        handlers.add(receivedEndpointSecurityHandler);

        BasicMessageHandlerChain<ArtifactResponse> handlerChain = new BasicMessageHandlerChain<ArtifactResponse>();
        handlerChain.setHandlers(handlers);

        try {
            handlerChain.initialize();
            handlerChain.doInvoke(context);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageHandlerException e) {
            throw new RuntimeException(e);
        }
    }

    public Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver =
                new StaticKeyInfoCredentialResolver(spCredentials.getCredential());

        Decrypter decrypter = new Decrypter(null,
                keyInfoCredentialResolver,
                new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }

    public void verifyAssertionSignature(Assertion assertion) {
        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }

        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());

            SignatureValidator.validate(assertion.getSignature(), spCredentials.getIdpVerificationCredential());

            logger.info("SAML Assertion signature verified");
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    public void logAssertionAttributes(Assertion assertion) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            logger.info("Attribute name: " + attribute.getName());
            for (XMLObject attributeValue : attribute.getAttributeValues()) {
                logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
            }
        }
    }

    public void logAuthenticationInstant(Assertion assertion) {
        logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
    }

    public void logAuthenticationMethod(Assertion assertion) {
        logger.info("Authentication method: " + assertion.getAuthnStatements().get(0)
                .getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
    }

    public EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response) artifactResponse.getMessage();
        return response.getEncryptedAssertions().get(0);
    }
}
