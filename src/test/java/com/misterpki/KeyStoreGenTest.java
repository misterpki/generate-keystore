package com.misterpki;

import java.security.KeyStore;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyStoreGenTest {

  @Test
  public void testAlias() throws Exception {
    final KeyStore keyStore = KeyStoreGen.generatePKCS12KeyStore("changeit");
    assertTrue(keyStore.containsAlias("symm-key"));
    assertTrue(keyStore.containsAlias("asymm-key"));
  }
}
