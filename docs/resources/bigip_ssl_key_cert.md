---
layout: "bigip"
page_title: "BIG-IP: bigip_ssl_key_cert"
subcategory: "System"
description: |-
  Provides details about bigip_ssl_key_cert resource
---

# bigip_ssl_key_cert

`bigip_ssl_key_cert` This resource will import SSL certificate and key on BIG-IP LTM. 
The certificate and the key can be imported from files on the local disk, in PEM format


## Example Usage

### Basic Usage with File

```hcl
resource "bigip_ssl_key_cert" "testkeycert" {
  partition    = "Common"
  key_name     = "ssl-test-key"
  key_content  = file("key.pem")
  cert_name    = "ssl-test-cert"
  cert_content = file("certificate.pem")
}
```

### Usage with Ephemeral Resources (Write-Only)

Using `ephemeral` resources ensures that the private key is never stored in the Terraform state file or on disk.

```hcl
ephemeral "tls_private_key" "example" {
  algorithm = "RSA"
}

ephemeral "tls_self_signed_cert" "example" {
  key_algorithm   = "RSA"
  private_key_pem = ephemeral.tls_private_key.example.private_key_pem

  subject {
    common_name  = "example.com"
    organization = "ACME Examples, Inc"
  }

  validity_period_hours = 12

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "bigip_ssl_key_cert" "example" {
  partition               = "Common"
  key_name                = "example.key"
  key_content_wo          = ephemeral.tls_private_key.example.private_key_pem
  key_content_wo_version  = 1

  cert_name               = "example.crt"
  cert_content_wo         = ephemeral.tls_self_signed_cert.example.cert_pem
  cert_content_wo_version = 1
}
```

## Argument Reference


* `key_name`- (Required,type `string`) Name of the SSL key to be Imported on to BIGIP.

* `key_content` - (Optional) Content of the SSL key. Typically used with the `file` function to read from a file on the local disk.

* `key_content_wo` - (Optional) Content of the SSL key. This attribute is write-only and will not be stored in the state file. Passing this attribute instead of `key_content` is useful when using ephemeral resources to ensure sensitive data is not persisted.

* `key_content_wo_version` - (Optional) This attribute is used to trigger an update when `key_content_wo` changes. If the content of the key changes, you must increment this version number to force Terraform to update the resource.

* `cert_name`- (Required,type `string`) Name of the SSL certificate to be Imported on to BIGIP.

* `cert_content` - (Optional) Content of the SSL certificate. Typically used with the `file` function to read from a file on the local disk.

* `cert_content_wo` - (Optional) Content of the SSL certificate. This attribute is write-only and will not be stored in the state file. Passing this attribute instead of `cert_content` is useful when using ephemeral resources.

* `cert_content_wo_version` - (Optional) This attribute is used to trigger an update when `cert_content_wo` changes. If the content of the certificate changes, you must increment this version number to force Terraform to update the resource.

* `partition` - (Optional,type `string`) Partition on to SSL certificate and key to be imported.

* `passphrase` - (Optional,type `string`) Passphrase on the SSL key.

* `cert_monitoring_type` - (Optional,type `string`) Specifies the type of monitoring used.

* `issuer_cert` - (Optional,type `string`) Specifies the issuer certificate.

* `cert_ocsp` - (Optional,type `string`) Specifies the OCSP responder.


## Attribute Reference

In addition to the arguments listed above, the following computed attributes are exported:

* `id` - identifier of the resource.

* `key_full_path` - full path of the SSL key on the BIGIP.

* `cert_full_path` - full path of the SSL certificate on the BIGIP.
