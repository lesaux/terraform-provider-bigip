---
layout: "bigip"
page_title: "BIG-IP: bigip_ssl_certificate"
subcategory: "System"
description: |-
  Provides details about bigip_ssl_certificate resource
---

# bigip_ssl_certificate

`bigip_ssl_certificate` This resource will import SSL certificates on BIG-IP LTM. 
Certificates can be imported from certificate files on the local disk, in PEM format


## Example Usage

```hcl
resource "bigip_ssl_certificate" "test-cert" {
  name      = "servercert.crt"
  content   = file("servercert.crt")
  partition = "Common"
}
```

### Usage with Ephemeral Resources (Write-Only)

```hcl
# Ephemeral TLS certificate (write-only; not stored in state)
ephemeral "tls_self_signed_cert" "example" {
  subject {
    common_name  = "example.com"
  }

  validity_period_hours = 8760
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "bigip_ssl_certificate" "example" {
  name               = "servercert.crt"
  content_wo         = ephemeral.tls_self_signed_cert.example.cert_pem
  content_wo_version = "1"
  partition          = "Common"
}
```

## Argument Reference


* `name`- (Required) Name of the SSL Certificate to be Imported on to BIGIP

* `content` - (Optional, exactly one of `content` or `content_wo` must be specified) Content of certificate on Local Disk, path of SSL certificate can be provided to terraform `file` function.

* `content_wo` - (Required, exactly one of `content` or `content_wo` must be specified) Content of the SSL certificate. This attribute is write-only and will not be stored in the state file. Passing this attribute instead of `content` is useful when using ephemeral resources to ensure sensitive data is not persisted.

* `content_wo_version` - (Optional) This attribute is used to trigger an update when `content_wo` changes. If the content changes, you must change this string (e.g. increment version or use a checksum) to force Terraform to update the resource.

* `partition` - Partition on to SSL Certificate to be imported. The parameter is not required when running terraform import operation. In such case the name must be provided in full_path format.

* `monitoring_type` - Specifies the type of monitoring used.

* `issuer_cert` - Specifies the issuer certificate.

* `ocsp` - Specifies the OCSP responder.
