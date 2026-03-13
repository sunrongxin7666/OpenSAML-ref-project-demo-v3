package no.steras.opensamlbook.sp.filter;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.sp.config.SPProperties;
import no.steras.opensamlbook.sp.credential.SPCredentials;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class SamlAccessFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(SamlAccessFilter.class);
    public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
    public static final String GOTO_URL_SESSION_ATTRIBUTE = "gotoURL";

    private final SPProperties spProperties;
    private final SPCredentials spCredentials;

    public SamlAccessFilter(SPProperties spProperties, SPCredentials spCredentials) {
        this.spProperties = spProperties;
        this.spCredentials = spCredentials;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getSession().getAttribute(AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
            filterChain.doFilter(request, response);
        } else {
            setGotoURLOnSession(request);
            redirectUserForAuthentication(response);
        }
    }

    private void setGotoURLOnSession(HttpServletRequest request) {
        request.getSession().setAttribute(GOTO_URL_SESSION_ATTRIBUTE, request.getRequestURL().toString());
    }

    private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthnRequest();
        redirectUserWithRequest(httpServletResponse, authnRequest);
    }

    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {
        MessageContext context = new MessageContext();
        context.setMessage(authnRequest);

        SAMLPeerEntityContext peerEntityContext =
                context.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext =
                peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(getIDPEndpoint());

        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        signatureSigningParameters.setSigningCredential(spCredentials.getCredential());
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

        context.getSubcontext(SecurityParametersContext.class, true)
                .setSignatureSigningParameters(signatureSigningParameters);

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        logger.info("AuthnRequest: ");
        OpenSAMLUtils.logSAMLObject(authnRequest);

        logger.info("Redirecting to IDP");
        try {
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(spProperties.getIdp().getSsoService());
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(spProperties.getAssertionConsumerService());
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
        authnRequest.setIssuer(buildIssuer());
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
        return authnRequest;
    }

    private RequestedAuthnContext buildRequestedAuthnContext() {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;
    }

    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);
        return nameIDPolicy;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(spProperties.getEntityId());
        return issuer;
    }

    private Endpoint getIDPEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(spProperties.getIdp().getSsoService());
        return endpoint;
    }
}
