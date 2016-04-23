package no.steras.opensamlbook.sp;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Privat on 13/05/14.
 */
public class SPCredentials {
/*    private static final String KEY_STORE_PASSWORD = "password";
    private static final String KEY_STORE_ENTRY_PASSWORD = "password";
    private static final String KEY_STORE_PATH = "/SPKeystore.jks";
    private static final String KEY_ENTRY_ID = "SPKey";

    private static final Credential credential;

    static {
        try {
            KeyStore keystore = readKeystoreFromFile(KEY_STORE_PATH, KEY_STORE_PASSWORD);
            Map<String, String> passwordMap = new HashMap<String, String>();
            passwordMap.put(KEY_ENTRY_ID, KEY_STORE_ENTRY_PASSWORD);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criteria criteria = new EntityIDCriteria(KEY_ENTRY_ID);
            CriteriaSet criteriaSet = new CriteriaSet(criteria);

            credential = resolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new RuntimeException("Something went wrong reading credentials", e);
        }
    }

    private static KeyStore readKeystoreFromFile(String pathToKeyStore, String keyStorePassword) {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            InputStream inputStream = SPCredentials.class.getResourceAsStream(pathToKeyStore);
            keystore.load(inputStream, keyStorePassword.toCharArray());
            inputStream.close();
            return keystore;
        } catch (Exception e) {
            throw new RuntimeException("Something went wrong reading keystore", e);
        }
    }

    public static Credential getCredential() {
        return credential;
    }

    */
}
