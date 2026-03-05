package bigip

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// testResourceSSLPKCS12 creates a bigip_ssl_pkcs12 resource with passphrase protection.
var testResourceSSLPKCS12 = `
resource "bigip_ssl_pkcs12" "test" {
  name                   = "ssl-test-p12"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert.p12")
  p12_content_wo_version = "1"
  passphrase_wo          = "testpassphrase"
  passphrase_wo_version  = "1"
}
`

// testResourceSSLPKCS12Updated re-imports with a different cert/key pair and passphrase.
var testResourceSSLPKCS12Updated = `
resource "bigip_ssl_pkcs12" "test" {
  name                   = "ssl-test-p12"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert2.p12")
  p12_content_wo_version = "2"
  passphrase_wo          = "testpassphrase2"
  passphrase_wo_version  = "2"
}
`

// testResourceSSLPKCS12SuppressDiff changes only the file but NOT the version —
// the DiffSuppressFunc must suppress the diff and produce an empty plan.
var testResourceSSLPKCS12SuppressDiff = `
resource "bigip_ssl_pkcs12" "test" {
  name                   = "ssl-test-p12"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert2.p12")
  p12_content_wo_version = "1"
  passphrase_wo          = "testpassphrase2"
  passphrase_wo_version  = "1"
}
`
// testResourceSSLPKCS12IssuerBase is the baseline config without issuer_cert.
var testResourceSSLPKCS12IssuerBase = `
resource "bigip_ssl_pkcs12" "test_issuer" {
  name                   = "ssl-test-p12-issuer"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert.p12")
  p12_content_wo_version = "1"
  passphrase_wo          = "testpassphrase"
  passphrase_wo_version  = "1"
}
`

// testResourceSSLPKCS12IssuerUpdated adds issuer_cert without bumping content versions.
var testResourceSSLPKCS12IssuerUpdated = `
resource "bigip_ssl_pkcs12" "test_issuer" {
  name                   = "ssl-test-p12-issuer"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert.p12")
  p12_content_wo_version = "1"
  passphrase_wo          = "testpassphrase"
  passphrase_wo_version  = "1"
  issuer_cert            = "/Common/ca-bundle.crt"
}
`

// TestAccBigipSSLPKCS12Create tests basic create, idempotency, and update.
func TestAccBigipSSLPKCS12Create(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLPKCS12,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test", "name", "ssl-test-p12"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test", "partition", "Common"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test", "p12_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test", "passphrase_wo_version", "1"),
					// write-only attrs must not be in state
					resource.TestCheckNoResourceAttr("bigip_ssl_pkcs12.test", "p12_content_wo"),
					resource.TestCheckNoResourceAttr("bigip_ssl_pkcs12.test", "passphrase_wo"),
					// computed paths must be set
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test", "cert_full_path"),
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test", "key_full_path"),
				),
				Destroy: false,
			},
			{
				// Idempotency — re-apply same config, plan must be empty.
				Config:             testResourceSSLPKCS12,
				ExpectNonEmptyPlan: false,
			},
			{
				// Update: new P12 + new passphrase + bumped versions.
				Config: testResourceSSLPKCS12Updated,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test", "p12_content_wo_version", "2"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test", "passphrase_wo_version", "2"),
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test", "cert_full_path"),
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test", "key_full_path"),
				),
			},
			{
				// Import: verify the resource can be reconstructed from its ID alone.
				ResourceName:      "bigip_ssl_pkcs12.test",
				ImportState:       true,
				ImportStateVerify: true,
				// Write-only fields and version trackers can't be verified on import by design.
				ImportStateVerifyIgnore: []string{
					"p12_content_wo",
					"p12_content_wo_version",
					"passphrase_wo",
					"passphrase_wo_version",
				},
			},
		},
	})
}

// TestAccBigipSSLPKCS12SuppressDiff verifies that changing p12_content_wo without bumping
// p12_content_wo_version produces an empty plan (DiffSuppressFunc in effect).
func TestAccBigipSSLPKCS12SuppressDiff(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLPKCS12,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test", "p12_content_wo_version", "1"),
				),
			},
			{
				// Different P12 + different passphrase but same versions → no plan change.
				Config:             testResourceSSLPKCS12SuppressDiff,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccBigipSSLPKCS12IssuerCertUpdate verifies that modifying issuer_cert without
// touching P12 versions exercises the metadata-only ModifyCertificate path.
func TestAccBigipSSLPKCS12IssuerCertUpdate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLPKCS12IssuerBase,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_issuer", "name", "ssl-test-p12-issuer"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_issuer", "p12_content_wo_version", "1"),
				),
			},
			{
				// Add issuer_cert; content versions unchanged → only ModifyCertificate called.
				Config: testResourceSSLPKCS12IssuerUpdated,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_issuer", "p12_content_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_issuer", "issuer_cert", "/Common/ca-bundle.crt"),
				),
			},
			{
				// Idempotency after metadata update.
				Config:             testResourceSSLPKCS12IssuerUpdated,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// testResourceSSLPKCS12VersionMissing omits p12_content_wo_version while providing
// p12_content_wo — schema validation must reject it.
var testResourceSSLPKCS12VersionMissing = `
resource "bigip_ssl_pkcs12" "bad" {
  name           = "ssl-test-bad"
  partition      = "Common"
  p12_content_wo = "dGVzdA=="
}
`

// TestAccBigipSSLPKCS12ValidationVersionRequired verifies that omitting
// p12_content_wo_version when p12_content_wo is set causes a validation error.
func TestAccBigipSSLPKCS12ValidationVersionRequired(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      testResourceSSLPKCS12VersionMissing,
				ExpectError: regexp.MustCompile(`p12_content_wo_version`),
			},
		},
	})
}

// testResourceSSLPKCS12NoPassphrase installs a P12 with an empty passphrase
// so the key is stored unencrypted on BIG-IP.
var testResourceSSLPKCS12NoPassphrase = `
resource "bigip_ssl_pkcs12" "test_nopassphrase" {
  name                   = "ssl-test-p12-nopassphrase"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert_nopass.p12")
  p12_content_wo_version = "1"
}
`

// TestAccBigipSSLPKCS12NoPassphrase verifies that a P12 can be installed without
// a passphrase (plain unencrypted key on BIG-IP).
func TestAccBigipSSLPKCS12NoPassphrase(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLPKCS12NoPassphrase,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_nopassphrase", "name", "ssl-test-p12-nopassphrase"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_nopassphrase", "partition", "Common"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_nopassphrase", "p12_content_wo_version", "1"),
					resource.TestCheckNoResourceAttr("bigip_ssl_pkcs12.test_nopassphrase", "passphrase_wo"),
					resource.TestCheckNoResourceAttr("bigip_ssl_pkcs12.test_nopassphrase", "passphrase_wo_version"),
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test_nopassphrase", "cert_full_path"),
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test_nopassphrase", "key_full_path"),
				),
				Destroy: false,
			},
			{
				// Idempotency
				Config:             testResourceSSLPKCS12NoPassphrase,
				ExpectNonEmptyPlan: false,
			},
			{
				// Import: no passphrase fields to ignore so cert/key paths must round-trip.
				ResourceName:      "bigip_ssl_pkcs12.test_nopassphrase",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"p12_content_wo",
					"p12_content_wo_version",
				},
			},
		},
	})
}

// testResourceSSLPKCS12PassphraseRotateBase is the initial config with passphrase v1.
var testResourceSSLPKCS12PassphraseRotateBase = `
resource "bigip_ssl_pkcs12" "test_pprot" {
  name                   = "ssl-test-p12-pprot"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert.p12")
  p12_content_wo_version = "1"
  passphrase_wo          = "testpassphrase"
  passphrase_wo_version  = "1"
}
`

// testResourceSSLPKCS12PassphraseRotated keeps the same P12 but bumps the passphrase
// version, simulating a passphrase rotation without re-issuing the certificate.
var testResourceSSLPKCS12PassphraseRotated = `
resource "bigip_ssl_pkcs12" "test_pprot" {
  name                   = "ssl-test-p12-pprot"
  partition              = "Common"
  p12_content_wo         = filebase64("` + folder + `/../examples/serverkeycert.p12")
  p12_content_wo_version = "1"
  passphrase_wo          = "newpassphrase"
  passphrase_wo_version  = "2"
}
`

// TestAccBigipSSLPKCS12PassphraseRotation verifies that bumping passphrase_wo_version
// alone (no cert content change) triggers a re-install with the new passphrase.
func TestAccBigipSSLPKCS12PassphraseRotation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceSSLPKCS12PassphraseRotateBase,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_pprot", "passphrase_wo_version", "1"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_pprot", "p12_content_wo_version", "1"),
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test_pprot", "cert_full_path"),
				),
				Destroy: false,
			},
			{
				// Rotate passphrase only — p12_content_wo_version unchanged.
				// The resource must re-install (passphrase_wo_version changed) but the
				// cert on BIG-IP should be the same object (cert_full_path unchanged).
				Config: testResourceSSLPKCS12PassphraseRotated,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_pprot", "passphrase_wo_version", "2"),
					resource.TestCheckResourceAttr("bigip_ssl_pkcs12.test_pprot", "p12_content_wo_version", "1"),
					resource.TestCheckResourceAttrSet("bigip_ssl_pkcs12.test_pprot", "cert_full_path"),
				),
			},
			{
				// Idempotency after passphrase rotation.
				Config:             testResourceSSLPKCS12PassphraseRotated,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// testResourceSSLPKCS12InvalidBase64 provides a value that is not valid base64.
var testResourceSSLPKCS12InvalidBase64 = `
resource "bigip_ssl_pkcs12" "test_bad_b64" {
  name                   = "ssl-test-bad-b64"
  partition              = "Common"
  p12_content_wo         = "this-is-not-base64!!!"
  p12_content_wo_version = "1"
  passphrase_wo          = "secret"
  passphrase_wo_version  = "1"
}
`

// TestAccBigipSSLPKCS12InvalidBase64 verifies that a non-base64 p12_content_wo value
// is caught at apply time and returns a descriptive error.
func TestAccBigipSSLPKCS12InvalidBase64(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      testResourceSSLPKCS12InvalidBase64,
				ExpectError: regexp.MustCompile(`error decoding p12_content_wo as base64`),
			},
		},
	})
}
