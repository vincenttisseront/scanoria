// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Sonde TLS de b25-live (tests seulement) : compilée par b25-live, lancée par
// le JVM de l'image de Dependency-Track (« java -cp DIR TlsProbe URL »), avec le magasin de certificats
// par défaut de ce JVM, comme Dependency-Track lui-même. Affiche le code HTTP,
// ou « untrusted » si la chaîne ou le nom du certificat sont refusés, ou
// « error:<classe> » pour toute autre erreur.

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class TlsProbe {
    public static void main(String[] args) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        HttpRequest req = HttpRequest.newBuilder(URI.create(args[0])).timeout(Duration.ofSeconds(20)).build();
        try {
            System.out.println(client.send(req, HttpResponse.BodyHandlers.discarding()).statusCode());
        } catch (Exception e) {
            for (Throwable t = e; t != null; t = t.getCause()) {
                if (t instanceof javax.net.ssl.SSLException || t instanceof java.security.cert.CertificateException) {
                    System.out.println("untrusted");
                    return;
                }
            }
            System.out.println("error:" + e.getClass().getSimpleName());
        }
    }
}
