/*
Copyright 2019 F5 Networks Inc.
This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

package bigip

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	bigip "github.com/f5devcentral/go-bigip"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var folder1, _ = os.Getwd()
var SslkeyName = "serverkey.key"
var TestSslkeyName = fmt.Sprintf("/%s/%s", TestPartition, SslkeyName)

var TestSslKeyResource = `
resource "bigip_ssl_key" "test-key" {
        name = "` + SslkeyName + `"
        content = "${file("` + folder1 + `/../examples/serverkey.key")}"
        partition = "` + TestPartition + `"
}
`

func TestAccBigipSslKeyImportToBigip(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: testChecksslKeyDestroyed,
		Steps: []resource.TestStep{
			{
				Config: TestSslKeyResource,
				Check: resource.ComposeTestCheckFunc(
					testChecksslkeyExists(TestSslkeyName, true),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key", "name", SslkeyName),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key", "partition", TestPartition),
				),
			},
		},
	})
}

func TestAccBigipSslKeyTCs(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: testChecksslKeyDestroyed,
		Steps: []resource.TestStep{
			{
				Config: loadFixtureString("../examples/bigip_ssl_key.tf"),
				Check: resource.ComposeTestCheckFunc(
					testChecksslkeyExists("ssl-test-key-tc1", true),
					testChecksslkeyExists("ssl-test-key-tc2", true),
					testChecksslkeyExists("ssl-test-key-tc100", false),
					resource.TestCheckResourceAttr("bigip_ssl_key.ssl-test-key-tc1", "name", "ssl-test-key-tc1"),
					resource.TestCheckResourceAttr("bigip_ssl_key.ssl-test-key-tc2", "name", "ssl-test-key-tc2"),
				),
			},
			{
				Config: loadFixtureString("../examples/bigip_ssl_key.tf"),
				Check: resource.ComposeTestCheckFunc(
					testChecksslkeyExists("ssl-test-key-tc1", true),
					testChecksslkeyExists("ssl-test-key-tc2", true),
					resource.TestCheckResourceAttr("bigip_ssl_key.ssl-test-key-tc1", "name", "ssl-test-key-tc1"),
					resource.TestCheckResourceAttr("bigip_ssl_key.ssl-test-key-tc2", "name", "ssl-test-key-tc2"),
				),
			},
			{
				Config: loadFixtureString("../examples/bigip_ssl_cert_keys.tf"),
				Check: resource.ComposeTestCheckFunc(
					testChecksslkeyExists("ssl-test-key-tc1", true),
					testChecksslkeyExists("ssl-test-key-tc2", true),
					resource.TestCheckResourceAttr("bigip_ssl_key.ssl-test-key-tc1", "name", "ssl-test-key-tc1"),
					resource.TestCheckResourceAttr("bigip_ssl_key.ssl-test-key-tc2", "name", "ssl-test-key-tc2"),
				),
			},
		},
	})
}

func testChecksslkeyExists(name string, exists bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testAccProvider.Meta().(*bigip.BigIP)
		p, err := client.GetKey(name)
		if err != nil {
			return err
		}
		if exists && p == nil {
			return fmt.Errorf("SSL Key %s was not created.", name)
		}
		if !exists && p != nil {
			return fmt.Errorf("SSL Key  %s still exists.", name)
		}
		return nil
	}
}

func testChecksslKeyDestroyed(s *terraform.State) error {
	client := testAccProvider.Meta().(*bigip.BigIP)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "bigip_ssl_key" {
			continue
		}
		name := rs.Primary.ID
		var sslCertificatename = fmt.Sprintf("~%s~%s", TestPartition, name)
		certificate, err := client.GetKey(sslCertificatename)
		if err != nil {
			return err
		}
		if certificate != nil {
			return fmt.Errorf("SSL Key %s not destroyed.", sslCertificatename)
		}
	}
	return nil
}

var SslkeyName_wo = "serverkey_wo.key"
var TestSslkeyName_wo = fmt.Sprintf("/%s/%s", TestPartition, SslkeyName_wo)

var TestSslKeyResourceWriteOnly = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
resource "bigip_ssl_key" "test-key-wo" {
        name = "` + SslkeyName_wo + `"
        content_wo = ephemeral.tls_private_key.wo.private_key_pem
		content_wo_version : 1
        partition = "` + TestPartition + `"
}
`

var TestSslKeyResourceWriteOnlyUpdated = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "bigip_ssl_key" "test-key-wo" {
        name = "` + SslkeyName_wo + `"
        content_wo = ephemeral.tls_private_key.wo.private_key_pem
		content_wo_version : 2
        partition = "` + TestPartition + `"
}
`

// Test update with NO version change - should NOT update
var TestSslKeyResourceWriteOnlyNoVersionUpdate = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "bigip_ssl_key" "test-key-wo" {
        name = "` + SslkeyName_wo + `"
        content_wo = ephemeral.tls_private_key.wo.private_key_pem
		content_wo_version : 1
        partition = "` + TestPartition + `"
}
`

func TestAccBigipSslKeyWriteOnly(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: testChecksslKeyDestroyed,
		Steps: []resource.TestStep{
			{
				Config: TestSslKeyResourceWriteOnly,
				Check: resource.ComposeTestCheckFunc(
					testChecksslkeyExists(TestSslkeyName_wo, true),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "name", SslkeyName_wo),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "partition", TestPartition),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "content_wo_version", "1"),
				),
			},
			{
				Config: TestSslKeyResourceWriteOnlyUpdated,
				Check: resource.ComposeTestCheckFunc(
					testChecksslkeyExists(TestSslkeyName_wo, true),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "name", SslkeyName_wo),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "partition", TestPartition),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "content_wo_version", "2"),
				),
			},
		},
	})
}

func TestAccBigipSslKeyWriteOnlySuppressDiff(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers:    testAccProviders,
		CheckDestroy: testChecksslKeyDestroyed,
		Steps: []resource.TestStep{
			{
				Config: TestSslKeyResourceWriteOnly,
				Check: resource.ComposeTestCheckFunc(
					testChecksslkeyExists(TestSslkeyName_wo, true),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "name", SslkeyName_wo),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "partition", TestPartition),
					resource.TestCheckResourceAttr("bigip_ssl_key.test-key-wo", "content_wo_version", "1"),
				),
			},
			{
				// This step attempts to change content but without version change
				// Terraform should see NO changes because of DiffSuppressFunc
				Config:             TestSslKeyResourceWriteOnlyNoVersionUpdate,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

var TestSslKeyResourceWriteOnlyConflict = `
ephemeral "tls_private_key" "wo" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
resource "bigip_ssl_key" "test-key-wo-conflict" {
        name = "serverkey_wo_conflict.key"
        content = ephemeral.tls_private_key.wo.private_key_pem
        content_wo = ephemeral.tls_private_key.wo.private_key_pem
		content_wo_version : 1
        partition = "` + TestPartition + `"
}
`

func TestAccBigipSslKeyWriteOnlyConflict(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      TestSslKeyResourceWriteOnlyConflict,
				ExpectError: regexp.MustCompile("conflicts with content"),
			},
		},
	})
}
