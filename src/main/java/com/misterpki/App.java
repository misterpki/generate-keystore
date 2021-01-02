package com.misterpki;

import java.io.FileOutputStream;
import java.security.KeyStore;

public class App {

    public static void main( String[] args ) throws Exception {
        final KeyStore keyStore = KeyStoreGen.generatePKCS12KeyStore("changeit");
        final FileOutputStream fos = new FileOutputStream("keystore.p12");
        keyStore.store(fos, "changeit".toCharArray());
    }
}
