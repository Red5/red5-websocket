package org.red5.net.websocket;

import java.io.File;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;

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
		SSLContext context = getSslContext();
		// create the ssl filter using server mode
		SslFilter sslFilter = new SslFilter(context);
		return sslFilter;
	}

	private SSLContext getSslContext() {
		SSLContext sslContext = null;
		try {
			File keyStore = new File(keystoreFile);
			File trustStore = new File(truststoreFile);
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
	 * @param path contains keystore
	 */
	public void setKeystoreFile(String path) {
		this.keystoreFile = path;
	}

	/**
	 * Set truststore file path.
	 * 
	 * @param path contains truststore
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
