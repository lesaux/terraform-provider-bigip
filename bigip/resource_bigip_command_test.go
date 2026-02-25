/*
Copyright 2019 F5 Networks Inc.
This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
package bigip

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var TestCommandResource = `
resource "bigip_command" "test-command" {
  commands   = ["show sys version"]
}
`
var testCmd = "show sys version"

func TestAccBigipCommand_run(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: TestCommandResource,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_command.test-command", "commands.0", testCmd),
					resource.TestMatchResourceAttr("bigip_command.test-command", "command_result.0", regexp.MustCompile("^\nSys::Version\nMain Package\n {2}Product {5}BIG-IP\n {2}Version")),
				),
			},
		},
	})
}

// TestCommandResourceWriteOnly runs the same command but via commands_wo so it is
// never stored in state.
var TestCommandResourceWriteOnly = `
resource "bigip_command" "test-command-wo" {
  commands_wo         = ["show sys version"]
  commands_wo_version = "1"
}
`

// TestCommandResourceWriteOnlyV2 bumps the version to trigger a re-run.
var TestCommandResourceWriteOnlyV2 = `
resource "bigip_command" "test-command-wo" {
  commands_wo         = ["show sys version"]
  commands_wo_version = "2"
}
`

// TestCommandResourceWriteOnlyConflict sets both commands and commands_wo — must error.
var TestCommandResourceWriteOnlyConflict = `
resource "bigip_command" "test-command-wo-conflict" {
  commands            = ["show sys version"]
  commands_wo         = ["show sys version"]
  commands_wo_version = "1"
}
`

// TestAccBigipCommandWriteOnly verifies that commands_wo executes the command,
// that the command string is not stored in state, and that bumping the version
// triggers re-execution.
func TestAccBigipCommandWriteOnly(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				// Step 1: create — command runs, commands_wo not in state, version is.
				Config: TestCommandResourceWriteOnly,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_command.test-command-wo", "commands_wo_version", "1"),
					// commands_wo is write-only — must NOT appear in state.
					resource.TestCheckNoResourceAttr("bigip_command.test-command-wo", "commands_wo.0"),
					// command_result is populated from the actual run.
					resource.TestMatchResourceAttr("bigip_command.test-command-wo", "command_result.0", regexp.MustCompile("Sys::Version")),
				),
			},
			{
				// Step 2: same config, same version — DiffSuppressFunc must suppress
				// the commands_wo diff, producing an empty plan.
				Config:             TestCommandResourceWriteOnly,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: bump version — command re-runs.
				Config: TestCommandResourceWriteOnlyV2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("bigip_command.test-command-wo", "commands_wo_version", "2"),
					resource.TestMatchResourceAttr("bigip_command.test-command-wo", "command_result.0", regexp.MustCompile("Sys::Version")),
				),
			},
		},
	})
}

// TestAccBigipCommandWriteOnlyConflict verifies that setting both commands and
// commands_wo is rejected at plan time.
func TestAccBigipCommandWriteOnlyConflict(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAcctPreCheck(t)
		},
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      TestCommandResourceWriteOnlyConflict,
				ExpectError: regexp.MustCompile("conflicts with"),
			},
		},
	})
}
