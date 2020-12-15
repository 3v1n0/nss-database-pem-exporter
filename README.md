# NSS Database Certificates exporter

A simple tool to export all the trusted CA certificates in a NSS database
(aka nssdb, usually in `~/.pki/nssdb` or `/etc/pki/nssdb`) as a chained cert
PEM cert file.

    ./nss-database-pem-exporter > chained-certs.pem

You can verify the parsed content using:

    openssl crl2pkcs7 -nocrl -certfile chained-certs.pem | openssl pkcs7 -print_certs -text -noout

It defaults to `/etc/pki/nssdb`, use `NSS_DATABASE` env variable to override it.
