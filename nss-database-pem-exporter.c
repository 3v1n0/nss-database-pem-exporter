/*
 * This file is part of the nss-database-pem-exporter distribution.
 * Copyright (c) 2020 Marco Trevisan <marco.trevisan@canonical.com>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nss.h>
#include <nss/base64.h>
#include <nss/cert.h>
#include <nss/certdb.h>
#include <nss/pk11func.h>

#define NSS_DATABASE_PATH "/etc/pki/nssdb"

#define NS_CERT_HEADER "-----BEGIN CERTIFICATE-----"
#define NS_CERT_TRAILER "-----END CERTIFICATE-----"

static SECStatus
print_ascii_certificate (CERTCertDBHandle      *handle,
                         const CERTCertificate *cert)
{
  CERTCertList *certs;
  CERTCertListNode *node;

  certs = CERT_CreateSubjectCertList (NULL, handle, &cert->derSubject,
                                      PR_Now (), PR_FALSE);

  for (node = CERT_LIST_HEAD (certs); !CERT_LIST_END (node, certs);
       node = CERT_LIST_NEXT (node))
    {
      CERTCertificate *c = node->cert;

      fprintf (stdout, NS_CERT_HEADER "\n");
      fprintf (stdout, "%s\n",
               BTOA_DataToAscii (c->derCert.data, c->derCert.len));
      fprintf (stdout, NS_CERT_TRAILER "\n");
    }

  if (certs)
    CERT_DestroyCertList (certs);

  return SECSuccess;
}

const char *
get_cert_name (CERTCertListNode *node)
{
  CERTCertificate * cert = node->cert;
  const char *name = node->appData;

  if (name && *name != '\0')
    return name;

  name = cert->nickname;
  if (name && *name != '\0')
    return name;

  name = cert->emailAddr;
  if (name && *name != '\0')
    return name;

  return NULL;
}

bool
check_trusted_flags (unsigned int flags)
{
  if (!(flags & CERTDB_VALID_CA))
    return false;

  /* Just return true here in any case (to handle the 'c' flag)? */
  return (flags & (CERTDB_TRUSTED |
                   CERTDB_TRUSTED_CA |
                   CERTDB_TRUSTED_CLIENT_CA |
                   CERTDB_GOVT_APPROVED_CA)) != 0;
}

bool
cert_is_trusted (const CERTCertificate *cert)
{
  CERTCertTrust *trust = cert->trust;

  if (!trust)
    return false;

  if (check_trusted_flags (trust->sslFlags))
    return true;

  if (check_trusted_flags (trust->emailFlags))
    return true;

  if (check_trusted_flags (trust->objectSigningFlags))
    return true;

  return false;
}

static SECStatus
print_trusted_certificates (CERTCertDBHandle *handle)
{
  CERTCertList *list;
  CERTCertListNode *node;

  list = PK11_ListCerts (PK11CertListCA, NULL);
  for (node = CERT_LIST_HEAD (list); !CERT_LIST_END (node, list);
       node = CERT_LIST_NEXT (node))
    {
      CERTCertificate *cert = node->cert;
      const char *cert_name = get_cert_name (node);

      if (!(cert->nsCertType & NS_CERT_TYPE_CA))
        continue;

      fprintf (stderr, "Found CA certificate %s\n", cert_name);
      if (!cert)
        continue;

      if (!cert_is_trusted (cert))
        {
          fprintf (stderr, "Certificate %s is not a trusted CA certificate, ignoring\n",
                   cert_name);
          continue;
        }

      print_ascii_certificate (handle, cert);
    }

  if (list)
    CERT_DestroyCertList (list);
  return SECSuccess;
}

int
main (void)
{
  CERTCertDBHandle *certHandle;
  const char *nssdb;
  int exit_status = EXIT_SUCCESS;

  nssdb = getenv ("NSS_DATABASE");
  if (!nssdb || !*nssdb)
    nssdb = NSS_DATABASE_PATH;

  if (NSS_Initialize (nssdb, NULL, NULL,
                      "secmod.db", NSS_INIT_READONLY) != SECSuccess)
    {
      fprintf (stderr, "Failed to open database\n");
      return EXIT_FAILURE;
    }

  certHandle = CERT_GetDefaultCertDB ();
  if (print_trusted_certificates (certHandle) != SECSuccess)
    exit_status = EXIT_FAILURE;

  if (NSS_Shutdown () != SECSuccess)
    return EXIT_FAILURE;

  return exit_status;
}
