package com.github.ferstl.suisseid;


import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContexts;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

public class SuisseIdMain {

  // Client Authentication, see https://oidref.com/1.3.6.1.5.5.7.3.2
  private static final String CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2";

  public static void main(String[] args) throws Exception {
    KeyStore windowsMyKeyStore = loadWindowsKeyStore("Windows-MY");
    KeyStore windowsRootKeyStore = loadWindowsKeyStore("Windows-ROOT");

    SSLContext sslContext = SSLContexts.custom()
        .loadKeyMaterial(windowsMyKeyStore, new char[]{}, new MyPrivateKeyStrategy())
        .loadTrustMaterial(windowsRootKeyStore, null)
        .build();

    CloseableHttpClient httpClient = HttpClients.custom()
        .setSSLContext(sslContext)
        .build();

    HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
    RestTemplate restTemplate = new RestTemplate(requestFactory);

    ResponseEntity<String> result = restTemplate.getForEntity("https://gateint1.sic.ch/sic4chf/mdm", String.class);
    System.out.println(result);
  }

  private static KeyStore loadWindowsKeyStore(String name) {
    try {
      KeyStore keyStore = KeyStore.getInstance(name);
      keyStore.load(null, null);
      return keyStore;
    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new RuntimeException(e);
    }

  }

  private static class MyPrivateKeyStrategy implements PrivateKeyStrategy {

    @Override
    public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
      for (String alias : aliases.keySet()) {
        PrivateKeyDetails privateKeyDetails = aliases.get(alias);
        for (X509Certificate certificate : privateKeyDetails.getCertChain()) {
          try {
            certificate.checkValidity();
            List<String> extKeyUsage = certificate.getExtendedKeyUsage();
            if (extKeyUsage != null && extKeyUsage.contains(CLIENT_AUTH_OID)) {
              return alias;
            }
          } catch (CertificateExpiredException | CertificateNotYetValidException | CertificateParsingException e) {
            // just continue
          }
        }
      }

      return null;
    }
  }
}
