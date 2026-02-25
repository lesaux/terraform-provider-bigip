package bigip

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var testResourceSSLKeyCert = `
resource "bigip_ssl_key_cert" "testkeycert" {
  partition   = "Common"
  key_name    = "ssl-test-key"
  key_content = "${file("` + folder + `/../examples/serverkey.key")}"
  cert_name    = "ssl-test-cert"
  cert_content = "${file("` + folder + `/../examples/servercert.crt")}"
}
`

var sslProfileCertKey = `
resource "bigip_ssl_key_cert" "testkeycert" {
  partition   = "Common"
  key_name    = "ssl-test-key"
  key_content = "${file("` + folder + `/../examples/%s")}"
  cert_name    = "ssl-test-cert"
  cert_content = "${file("` + folder + `/../examples/%s")}"
}

resource "bigip_ltm_profile_server_ssl" "test-ServerSsl" {
  name          = "/Common/test-ServerSsl"
  defaults_from = "/Common/serverssl"
  authenticate  = "always"
  ciphers       = "DEFAULT"
  cert          = "/Common/ssl-test-cert"
  key           = "/Common/ssl-test-key"

  depends_on = [
	bigip_ssl_key_cert.testkeycert
  ]
}
`

var sslProfileCertKeyOCSP = `
resource "bigip_ssl_key_cert" "testkeycert" {
  partition            = "Common"
  key_name             = "ssl-test-key"
  key_content          = "${file("` + folder + `/../examples/mycertocspv2.pem")}"
  cert_name            = "ssl-test-cert"
  cert_content         = "${file("` + folder + `/../examples/mycertocspv2.crt")}"
  cert_monitoring_type = "ocsp"
  issuer_cert          = "/Common/MyCA"
  cert_ocsp            = "/Common/testocsp1"
}
`

func TestAccBigipSSLCertKeyCreate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		// CheckDestroy:
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLKeyCert,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "key_name", "ssl-test-key"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_name", "ssl-test-cert"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "partition", "Common"),
				),
				Destroy: false,
			},
			{
				Config: testResourceSSLKeyCert,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "key_name", "ssl-test-key"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_name", "ssl-test-cert"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "partition", "Common"),
				),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccBigipSSLCertKeyCreateCertKeyProfile(t *testing.T) {
	create := fmt.Sprintf(sslProfileCertKey, "serverkey.key", "servercert.crt")
	modify := fmt.Sprintf(sslProfileCertKey, "serverkey2.key", "servercert2.crt")
	crt1Content, _ := os.ReadFile(folder + `/../examples/` + "servercert.crt")
	key1Content, _ := os.ReadFile(folder + `/../examples/` + "serverkey.key")
	crt2Content, _ := os.ReadFile(folder + `/../examples/` + "servercert2.crt")
	key2Content, _ := os.ReadFile(folder + `/../examples/` + "serverkey2.key")

	log.Println(create)
	log.Println(modify)
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: create,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "key_name", "ssl-test-key"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_name", "ssl-test-cert"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "partition", "Common"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "key_content", string(key1Content)),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_content", string(crt1Content)),
				),
				Destroy: false,
			},
			{
				Config: modify,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "key_name", "ssl-test-key"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_name", "ssl-test-cert"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "partition", "Common"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "key_content", string(key2Content)),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_content", string(crt2Content)),
				),
			},
		},
	})
}

func TestAccBigipSSLCertKeyCreateCertKeyProfileOCSP(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: sslProfileCertKeyOCSP,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "key_name", "ssl-test-key"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_name", "ssl-test-cert"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "partition", "Common"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_monitoring_type", "ocsp"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "issuer_cert", "/Common/MyCA"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert", "cert_ocsp", "/Common/testocsp1"),
				),
			},
		},
	})
}

var testResourceSSLKeyCertWO = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
ephemeral "tls_self_signed_cert" "wo" {
  key_algorithm   = "RSA"
  private_key_pem = ephemeral.tls_private_key.wo.private_key_pem
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

resource "bigip_ssl_key_cert" "testkeycert_wo" {
  partition               = "Common"
  key_name                = "ssl-test-key-wo"
  key_content_wo          = ephemeral.tls_private_key.wo.private_key_pem
  key_content_wo_version  = "1"
  cert_name               = "ssl-test-cert-wo"
  cert_content_wo         = ephemeral.tls_self_signed_cert.wo.cert_pem
  cert_content_wo_version = "1"
}
`

var testResourceSSLKeyCertWOUpdated = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
ephemeral "tls_self_signed_cert" "wo" {
  key_algorithm   = "RSA"
  private_key_pem = ephemeral.tls_private_key.wo.private_key_pem
  subject {
    common_name  = "example.net"
    organization = "ACME Examples v2, Inc"
  }
  validity_period_hours = 24
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "bigip_ssl_key_cert" "testkeycert_wo" {
  partition               = "Common"
  key_name                = "ssl-test-key-wo"
  key_content_wo          = ephemeral.tls_private_key.wo.private_key_pem
  key_content_wo_version  = "2"
  cert_name               = "ssl-test-cert-wo"
  cert_content_wo         = ephemeral.tls_self_signed_cert.wo.cert_pem
  cert_content_wo_version = "2"
}
`

var testResourceSSLKeyCertWOUpdateNoVersion = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
ephemeral "tls_self_signed_cert" "wo" {
  key_algorithm   = "RSA"
  private_key_pem = ephemeral.tls_private_key.wo.private_key_pem
  subject {
    common_name  = "example.net"
    organization = "ACME Examples, Inc"
  }
  validity_period_hours = 24
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "bigip_ssl_key_cert" "testkeycert_wo" {
  partition               = "Common"
  key_name                = "ssl-test-key-wo"
  key_content_wo          = ephemeral.tls_private_key.wo.private_key_pem
  key_content_wo_version  = "1"
  cert_name               = "ssl-test-cert-wo"
  cert_content_wo         = ephemeral.tls_self_signed_cert.wo.cert_pem
  cert_content_wo_version = "1"
}
`

func TestAccBigipSSLCertKeyCreateWO(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLKeyCertWO,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "key_name", "ssl-test-key-wo"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "cert_name", "ssl-test-cert-wo"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "key_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "cert_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "partition", "Common"),
				),
				Destroy: false,
			},
			{
				// Test idempotency
				Config: testResourceSSLKeyCertWO,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "key_name", "ssl-test-key-wo"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "cert_name", "ssl-test-cert-wo"),
				),
				ExpectNonEmptyPlan: false,
			},
			{
				// Test Update
				Config: testResourceSSLKeyCertWOUpdated,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "key_content_wo_version", "2"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "cert_content_wo_version", "2"),
				),
			},
		},
	})
}

func TestAccBigipSSLCertKeyCreateWOSuppressDiff(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLKeyCertWO,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "key_name", "ssl-test-key-wo"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "cert_name", "ssl-test-cert-wo"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "key_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_wo", "cert_content_wo_version", "1"),
				),
			},
			{
				// This step attempts to change content but without version change
				// Terraform should see NO changes because of DiffSuppressFunc
				Config:             testResourceSSLKeyCertWOUpdateNoVersion,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// testResourceSSLKeyCertWOMetadataBase creates a key+cert resource using write-only
// content with no metadata fields set. Used as the baseline for metadata-only update tests.
var testResourceSSLKeyCertWOMetadataBase = `
ephemeral "tls_private_key" "meta" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
ephemeral "tls_self_signed_cert" "meta" {
  key_algorithm   = "RSA"
  private_key_pem = ephemeral.tls_private_key.meta.private_key_pem
  subject {
    common_name  = "meta-test.example.com"
    organization = "ACME"
  }
  validity_period_hours = 12
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "bigip_ssl_key_cert" "testkeycert_meta" {
  partition               = "Common"
  key_name                = "ssl-test-key-meta"
  key_content_wo          = ephemeral.tls_private_key.meta.private_key_pem
  key_content_wo_version  = "1"
  cert_name               = "ssl-test-cert-meta"
  cert_content_wo         = ephemeral.tls_self_signed_cert.meta.cert_pem
  cert_content_wo_version = "1"
}
`

// testResourceSSLKeyCertWOMetadataUpdated keeps the same content versions so that
// certPath remains empty in the Update function, but adds issuer_cert to trigger
// the metadata-only ModifyCertificate branch instead of UpdateCertificate.
var testResourceSSLKeyCertWOMetadataUpdated = `
ephemeral "tls_private_key" "meta" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
ephemeral "tls_self_signed_cert" "meta" {
  key_algorithm   = "RSA"
  private_key_pem = ephemeral.tls_private_key.meta.private_key_pem
  subject {
    common_name  = "meta-test.example.com"
    organization = "ACME"
  }
  validity_period_hours = 12
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "bigip_ssl_key_cert" "testkeycert_meta" {
  partition               = "Common"
  key_name                = "ssl-test-key-meta"
  key_content_wo          = ephemeral.tls_private_key.meta.private_key_pem
  key_content_wo_version  = "1"
  cert_name               = "ssl-test-cert-meta"
  cert_content_wo         = ephemeral.tls_self_signed_cert.meta.cert_pem
  cert_content_wo_version = "1"
  # issuer_cert added without bumping content versions — exercises the metadata-only
  # ModifyCertificate path; UpdateCertificate must NOT be called here.
  issuer_cert = "/Common/ca-bundle.crt"
}
`

// TestAccBigipSSLCertKeyWriteOnlyMetadataUpdate verifies that when only metadata
// fields change (issuer_cert here) while content version stays the same, the update
// logic takes the metadata-only ModifyCertificate branch and does NOT re-upload content.
func TestAccBigipSSLCertKeyWriteOnlyMetadataUpdate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				// Step 1: create with write-only content, no metadata fields.
				Config: testResourceSSLKeyCertWOMetadataBase,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "key_name", "ssl-test-key-meta"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "cert_name", "ssl-test-cert-meta"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "key_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "cert_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "partition", "Common"),
				),
			},
			{
				// Step 2: add issuer_cert WITHOUT changing content versions.
				// certPath will be "" in resourceBigipSSLKeyCertUpdate (HasChange on versions is false),
				// so the update must go through the metadata-only ModifyCertificate branch.
				Config: testResourceSSLKeyCertWOMetadataUpdated,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "key_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "cert_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_key_cert.testkeycert_meta", "issuer_cert", "/Common/ca-bundle.crt"),
				),
			},
			{
				// Step 3: re-apply metadata config — plan must be empty (no drift).
				Config:             testResourceSSLKeyCertWOMetadataUpdated,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

var testResourceSSLKeyCertWOConflict = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
ephemeral "tls_self_signed_cert" "wo" {
  key_algorithm   = "RSA"
  private_key_pem = ephemeral.tls_private_key.wo.private_key_pem
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

resource "bigip_ssl_key_cert" "testkeycert_wo_conflict" {
  partition               = "Common"
  key_name                = "ssl-test-key-wo-conflict"

  key_content             = ephemeral.tls_private_key.wo.private_key_pem
  key_content_wo          = ephemeral.tls_private_key.wo.private_key_pem
  key_content_wo_version  = "1"

  cert_name               = "ssl-test-cert-wo-conflict"
  cert_content            = ephemeral.tls_self_signed_cert.wo.cert_pem
  cert_content_wo         = ephemeral.tls_self_signed_cert.wo.cert_pem
  cert_content_wo_version = "1"
}
`

func TestAccBigipSSLCertKeyCreateWOConflict(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      testResourceSSLKeyCertWOConflict,
				ExpectError: regexp.MustCompile("conflicts with"),
			},
		},
	})
}
