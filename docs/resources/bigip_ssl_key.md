---
layout: "bigip"
page_title: "BIG-IP: bigip_ssl_key"
subcategory: "System"
description: |-
  Provides details about bigip_ssl_key resource
---

# bigip_ssl_key

`bigip_ssl_key` This resource will import SSL certificate key on BIG-IP LTM. 
Certificate key can be imported from certificate key files on the local disk, in PEM format


## Example Usage

### Basic Usage with File

```hcl
resource "bigip_ssl_key" "test-key" {
  name      = "serverkey.key"
  content   = file("serverkey.key")
  partition = "Common"
}
```

### Usage with Ephemeral Resources (Write-Only)

Using `ephemeral` resources ensures that the private key is never stored in the Terraform state file or on disk.

```hcl
ephemeral "tls_private_key" "example" {
  algorithm = "RSA"
}

resource "bigip_ssl_key" "example" {
  name               = "example.key"
  content_wo         = ephemeral.tls_private_key.example.private_key_pem
  content_wo_version = "1"
  partition          = "Common"
  passphrase_wo      = "secret123"
  passphrase_wo_version = "1"
}
```

## Argument Reference


* `name`- (Required,type `string`) Name of the SSL Certificate key to be Imported on to BIGIP

* `content` - (Optional) Content of the SSL certificate key. Typically used with the `file` function to read from a file on the local disk.

* `content_wo` - (Optional) Content of the SSL certificate key. This attribute is write-only and will not be stored in the state file. Passing this attribute instead of `content` is useful when using ephemeral resources to ensure sensitive data is not persisted.

* `content_wo_version` - (Optional) This attribute is used to trigger an update when `content_wo` changes. If the content of the key changes, you must change this string (e.g. increment version or use a checksum) to force Terraform to update the resource.

* `passphrase` - (Optional) Passphrase on key.

* `passphrase_wo` - (Optional) Passphrase on key. This attribute is write-only and will not be stored in the state file. Passing this attribute instead of `passphrase` is useful when using ephemeral resources to ensure sensitive data is not persisted.

* `passphrase_wo_version` - (Optional) This attribute is used to trigger an update when `passphrase_wo` changes. If the passphrase changes, you must change this string (e.g. increment version or use a checksum) to force Terraform to update the resource.

* `partition` - (Optional,type `string`) Partition on to SSL Certificate key to be imported. The parameter is not required when running terraform import operation. In such case the name must be provided in `full_path` format.

