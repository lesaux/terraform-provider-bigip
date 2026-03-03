package bigip

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	bigip "github.com/f5devcentral/go-bigip"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceBigipSslKey() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceBigipSslKeyCreate,
		ReadContext:   resourceBigipSslKeyRead,
		UpdateContext: resourceBigipSslKeyUpdate,
		DeleteContext: resourceBigipSslKeyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of SSL Certificate key with .key extension",
				ForceNew:    true,
			},
			"content": {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				Description:  "Content of SSL certificate key present on local Disk",
				ExactlyOneOf: []string{"content", "content_wo"},
			},
			"content_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "Content of SSL certificate key present on local Disk - Write Only",
				ExactlyOneOf: []string{"content", "content_wo"},
				RequiredWith: []string{"content_wo_version"},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return !d.HasChange("content_wo_version")
				},
			},
			"content_wo_version": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "",
				Description:  "Version of Content of SSL certificate key present on local Disk - Write Only",
				RequiredWith: []string{"content_wo"},
			},
			"partition": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "Common",
				Description:  "Partition of ssl certificate key",
				ValidateFunc: validatePartitionName,
			},
			"full_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Full Path Name of ssl key",
			},
		},
	}
}

func resourceBigipSslKeyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)
	name := d.Get("name").(string)
	log.Println("[INFO] Certificate Key Name " + name)
	certpath := d.Get("content").(string)
	if certpath == "" {
		certpath = d.Get("content_wo").(string)
	}
	partition := d.Get("partition").(string)
	}
	/*if !strings.HasSuffix(name, ".key") {
		name = name + ".key"
	}*/

	sourcePath, err := client.UploadKey(name, certpath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error in Uploading certificate key (%s): %s", name, err))
	}
	certkey := bigip.Key{
		Name:       name,
		SourcePath: sourcePath,
		Partition:  partition,
	}
	log.Printf("[DEBUG] certkey: %+v\n", certkey)
	err = client.AddKey(&certkey)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(name)
	return resourceBigipSslKeyRead(ctx, d, meta)
}

func resourceBigipSslKeyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)
	name := d.Id()
	log.Println("[INFO] Reading Certificate key: " + name)
	/*if !strings.HasSuffix(name, ".key") {
		name = name + ".key"
	}*/
	partition := d.Get("partition").(string)
	if partition == "" {
		if !strings.HasPrefix(name, "/") {
			err := errors.New("the name must be in full_path format when partition is not specified")
			fmt.Print(err)
		}
	} else {
		if !strings.HasPrefix(name, "/") {
			name = "/" + partition + "/" + name
		}
	}
	certkey, err := client.GetKey(name)
	if err != nil {
		return diag.FromErr(err)
	}
	if certkey == nil {
		return diag.Errorf("Reading Certificate key failed with key:%v", certkey)
	}
	log.Printf("[INFO] SSL key content:%+v", certkey)
	_ = d.Set("name", certkey.Name)
	_ = d.Set("partition", certkey.Partition)
	_ = d.Set("full_path", certkey.FullPath)
	return nil
}

func resourceBigipSslKeyUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)
	name := d.Id()
	log.Println("[INFO] Certificate key Name " + name)
	certpath := d.Get("content").(string)
	if certpath == "" {
		// content_wo is write-only (never stored in state), so d.HasChange("content_wo")
		// always returns true when the field is configured. Use the version field instead,
		// which IS stored in state and is the user-controlled signal for "key changed".
		if d.HasChange("content_wo_version") {
			certpath = d.Get("content_wo").(string)
		}
	} else {
		if !d.HasChange("content") {
			certpath = ""
		}
	}
	/*if !strings.HasSuffix(name, ".key") {
		name = name + ".key"
	}*/
	partition := d.Get("partition").(string)
	}

	var sourcePath string
	var err error
	if certpath != "" {
		sourcePath, err = client.UploadKey(name, certpath)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error in Uploading certificate key (%s): %s", name, err))
		}
	}

	certkey := bigip.Key{
		Name:       name,
		SourcePath: sourcePath,
		Partition:  partition,
	}
	keyName := fmt.Sprintf("/%s/%s", partition, name)
	err = client.ModifyKey(keyName, &certkey)
	if err != nil {
		return diag.FromErr(err)
	}
	return resourceBigipSslKeyRead(ctx, d, meta)
}

func resourceBigipSslKeyDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)
	name := d.Id()
	log.Println("[INFO] Deleting Certificate key" + name)
	/*if !strings.HasSuffix(name, ".key") {
		name = name + ".key"
	}*/
	partition := d.Get("partition").(string)
	name = "/" + partition + "/" + name
	err := client.DeleteKey(name)
	if err != nil {
		log.Printf("[ERROR] Unable to Delete Pool   (%s) (%v) ", name, err)
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
