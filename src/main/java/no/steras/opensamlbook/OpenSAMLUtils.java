package no.steras.opensamlbook;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Privat on 4/6/14.
 */
public class OpenSAMLUtils {
    private static Logger logger = LoggerFactory.getLogger(OpenSAMLUtils.class);
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

    static {
        secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    }

    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object = null;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }

    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static void logSAMLObject(final XMLObject object) {
        try {
            DocumentBuilder builder;
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);

            builder = factory.newDocumentBuilder();

            Document document = builder.newDocument();
            Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
            out.marshall(object, document);

            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(document);
            transformer.transform(source, result);
            String xmlString = result.getWriter().toString();

            logger.info(xmlString);
        } catch (ParserConfigurationException e) {
            logger.error(e.getMessage(), e);
        } catch (MarshallingException e) {
            logger.error(e.getMessage(), e);
        } catch (TransformerException e) {
            logger.error(e.getMessage(), e);
        }
    }
/*
    public static Envelope wrapInSOAPEnvelope(final XMLObject xmlObject) throws IllegalAccessException {
        Envelope envelope = OpenSAMLUtils.buildSAMLObject(Envelope.class);
        Body body = OpenSAMLUtils.buildSAMLObject(Body.class);

        body.getUnknownXMLObjects().add(xmlObject);

        envelope.setBody(body);

        return envelope;
    }
    */
}
