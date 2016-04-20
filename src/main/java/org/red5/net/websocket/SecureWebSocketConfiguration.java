/*
 * RED5 Open Source Flash Server - https://github.com/red5
 * 
 * Copyright 2006-2015 by respective authors (see below). All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.red5.net.websocket;

import java.io.File;
import java.io.NotActiveException;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.apache.mina.filter.ssl.KeyStoreFactory;
import org.apache.mina.filter.ssl.SslContextFactory;
import org.apache.mina.filter.ssl.SslFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides configuration support for WSS protocol.
 * 
 * @author Paul Gregoire (mondain@gmail.com)
 */
public class SecureWebSocketConfiguration {

    private static Logger log = LoggerFactory.getLogger(SecureWebSocketConfiguration.class);

    /**
     * Password for accessing the keystore.
     */
    private String keystorePassword;

    /**
     * Password for accessing the truststore.
     */
    private String truststorePassword;

    /**
     * Stores the keystore path.
     */
    private String keystoreFile;

    /**
     * Stores the truststore path.
     */
    private String truststoreFile;

    /**
     * The keystore type, valid options are JKS and PKCS12
     */
    @SuppressWarnings("unused")
    private String keystoreType = "JKS";

    public SslFilter getSslFilter() throws Exception {
        if (keystoreFile == null || truststoreFile == null) {
            throw new NotActiveException("Keystore or truststore are null");
        }
        SSLContext context = getSslContext();
        // create the ssl filter using server mode
        SslFilter sslFilter = new SslFilter(context);
        return sslFilter;
    }

    private SSLContext getSslContext() {
        SSLContext sslContext = null;
        try {
            log.debug("Keystore: {}", keystoreFile);
            File keyStore = new File(keystoreFile);
            log.trace("Keystore - read: {} path: {}", keyStore.canRead(), keyStore.getCanonicalPath());
            log.debug("Truststore: {}", truststoreFile);
            File trustStore = new File(truststoreFile);
            log.trace("Truststore - read: {} path: {}", trustStore.canRead(), trustStore.getCanonicalPath());
            if (keyStore.exists() && trustStore.exists()) {
                final KeyStoreFactory keyStoreFactory = new KeyStoreFactory();
                keyStoreFactory.setDataFile(keyStore);
                keyStoreFactory.setPassword(keystorePassword);

                final KeyStoreFactory trustStoreFactory = new KeyStoreFactory();
                trustStoreFactory.setDataFile(trustStore);
                trustStoreFactory.setPassword(truststorePassword);

                final SslContextFactory sslContextFactory = new SslContextFactory();
                final KeyStore ks = keyStoreFactory.newInstance();
                sslContextFactory.setKeyManagerFactoryKeyStore(ks);

                final KeyStore ts = trustStoreFactory.newInstance();
                sslContextFactory.setTrustManagerFactoryKeyStore(ts);
                sslContextFactory.setKeyManagerFactoryKeyStorePassword(keystorePassword);
                sslContext = sslContextFactory.newInstance();
                log.debug("SSL provider is: {}", sslContext.getProvider());

                SSLParameters params = sslContext.getDefaultSSLParameters();
                log.debug("SSL context params - need client auth: {} want client auth: {} endpoint id algorithm: {}", params.getNeedClientAuth(), params.getWantClientAuth(), params.getEndpointIdentificationAlgorithm());
                String[] supportedProtocols = params.getProtocols();
                for (String protocol : supportedProtocols) {
                    log.debug("SSL context supported protocol: {}", protocol);
                }
            } else {
                log.warn("Keystore or Truststore file does not exist");
            }
        } catch (Exception ex) {
            log.error("Exception getting SSL context", ex);
        }
        return sslContext;
    }

    /**
     * Password used to access the keystore file.
     * 
     * @param password
     */
    public void setKeystorePassword(String password) {
        this.keystorePassword = password;
    }

    /**
     * Password used to access the truststore file.
     * 
     * @param password
     */
    public void setTruststorePassword(String password) {
        this.truststorePassword = password;
    }

    /**
     * Set keystore data from a file.
     * 
     * @param path
     *            contains keystore
     */
    public void setKeystoreFile(String path) {
        this.keystoreFile = path;
    }

    /**
     * Set truststore file path.
     * 
     * @param path
     *            contains truststore
     */
    public void setTruststoreFile(String path) {
        this.truststoreFile = path;
    }

    /**
     * Set the key store type, JKS or PKCS12.
     * 
     * @param keystoreType
     */
    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

}
