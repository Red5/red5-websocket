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
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.apache.mina.filter.ssl.KeyStoreFactory;
import org.apache.mina.filter.ssl.SslContextFactory;
import org.apache.mina.filter.ssl.SslFilter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
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
     * Names of the SSL cipher suites which are currently enabled for use.
     */
    private String[] cipherSuites;

    /**
     * Names of the protocol versions which are currently enabled for use.
     */
    private String[] protocols;

    static {
        // add bouncycastle security provider
        int insertedAt = Security.insertProviderAt(new BouncyCastleProvider(), 1);
        log.debug("BC provider inserted at position: {}", insertedAt);
        //insertedAt = Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        //log.debug("BC JSSE provider inserted at position: {}", insertedAt);
        //Security.addProvider(new BouncyCastleProvider());
        if (log.isTraceEnabled()) {
            Provider[] providers = Security.getProviders();
            for (Provider provider : providers) {
                log.trace("Provider: {} = {}", provider.getName(), provider.getInfo());
            }
        }
    }

    public SslFilter getSslFilter() throws Exception {
        if (keystoreFile == null || truststoreFile == null) {
            throw new NotActiveException("Keystore or truststore are null");
        }
        SSLContext context = getSslContext();
        if (context == null) {
            throw new NotActiveException("SSLContext is null");
        }
        // create the ssl filter using server mode
        SslFilter sslFilter = new SslFilter(context);
        if (cipherSuites != null) {
            sslFilter.setEnabledCipherSuites(cipherSuites);
        }
        if (protocols != null) {
            if (log.isDebugEnabled()) {
                log.debug("Using these protocols: {}", Arrays.toString(protocols));
            }
            sslFilter.setEnabledProtocols(protocols);
        }
        return sslFilter;
    }

    private SSLContext getSslContext() {
        // create the ssl context
        SSLContext sslContext = null;
        try {
            log.debug("Keystore: {}", keystoreFile);
            File keyStore = new File(keystoreFile);
            log.trace("Keystore - read: {} path: {}", keyStore.canRead(), keyStore.getCanonicalPath());
            log.debug("Truststore: {}", truststoreFile);
            File trustStore = new File(truststoreFile);
            log.trace("Truststore - read: {} path: {}", trustStore.canRead(), trustStore.getCanonicalPath());
            if (keyStore.exists() && trustStore.exists()) {
                // ssl context factory
                final SslContextFactory sslContextFactory = new SslContextFactory();
                // enforce TLSv1.2 otherwise we may get a lesser protocol
                sslContextFactory.setProtocol("TLSv1.2");
                // get provider
                Provider prov = Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
                if (prov != null) {
                    if (log.isDebugEnabled()) {
                        for (String prop : prov.stringPropertyNames()) {
                            log.debug("Property name: {}", prop);
                        }
                        Set<Service> svcs = prov.getServices();
                        for (Service svc : svcs) {
                            log.debug("Service - type: {} class: {}", svc.getType(), svc.getClassName());
                        }
                    }
                    sslContextFactory.setProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
                    //keyStoreFactory.setProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
                    //trustStoreFactory.setProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
                } else {
                    // use whatever default is available
                    log.debug("BouncyCastleJsseProvider not found");
                }
                // keystore
                final KeyStoreFactory keyStoreFactory = new KeyStoreFactory();
                keyStoreFactory.setDataFile(keyStore);
                keyStoreFactory.setPassword(keystorePassword);
                // truststore
                final KeyStoreFactory trustStoreFactory = new KeyStoreFactory();
                trustStoreFactory.setDataFile(trustStore);
                trustStoreFactory.setPassword(truststorePassword);
                // get keystore
                final KeyStore ks = keyStoreFactory.newInstance();
                sslContextFactory.setKeyManagerFactoryKeyStore(ks);
                // get truststore
                final KeyStore ts = trustStoreFactory.newInstance();
                sslContextFactory.setTrustManagerFactoryKeyStore(ts);
                sslContextFactory.setKeyManagerFactoryKeyStorePassword(keystorePassword);
                // get ssl context
                sslContext = sslContextFactory.newInstance();
                log.debug("SSL provider: {}", sslContext.getProvider());
                // SNI state
                boolean sniEnabled = Boolean.valueOf(System.getProperty("jsse.enableSNIExtension", "false"));
                // get ssl context parameters
                SSLParameters params = sslContext.getDefaultSSLParameters();
                if (log.isDebugEnabled()) {
                    log.debug("SSL context params - need client auth: {} want client auth: {} endpoint id algorithm: {}", params.getNeedClientAuth(), params.getWantClientAuth(), params.getEndpointIdentificationAlgorithm());
                    String[] supportedProtocols = params.getProtocols();
                    if (supportedProtocols != null) {
                        for (String protocol : supportedProtocols) {
                            log.debug("SSL context supported protocol: {}", protocol);
                        }
                    } else {
                        log.debug("No protocols");
                    }
                    String[] supportedCiphers = params.getCipherSuites();
                    if (supportedCiphers != null) {
                        for (String cipher : supportedCiphers) {
                            log.debug("SSL context supported cipher: {}", cipher);
                        }
                    } else {
                        log.debug("No ciphers");
                    }
                    // http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SNIExamples
                    log.debug("SNI extension enabled: {}", sniEnabled);
                    List<SNIServerName> serverNames = params.getServerNames();
                    if (serverNames != null) {
                        for (SNIServerName sname : serverNames) {
                            log.debug("SNI server name: {}", sname);
                        }
                    } else {
                        log.debug("No SNI server names specified");
                    }
                    Collection<SNIMatcher> sniMatchers = params.getSNIMatchers();
                    if (sniMatchers != null) {
                        for (SNIMatcher sniMatcher : sniMatchers) {
                            log.debug("SNI matcher: {}", sniMatcher);
                        }
                    } else {
                        log.debug("No SNI matchers specified");
                    }
                }
                if (sniEnabled) {
                    SNIMatcher matcher = SNIHostName.createSNIMatcher("");
                    Collection<SNIMatcher> matchers = new ArrayList<>(1);
                    matchers.add(matcher);
                    params.setSNIMatchers(matchers);
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

    public String[] getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(String[] cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public String[] getProtocols() {
        return protocols;
    }

    public void setProtocols(String[] protocols) {
        this.protocols = protocols;
    }

}
