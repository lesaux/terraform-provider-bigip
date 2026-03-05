package bigip

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	bigip "github.com/f5devcentral/go-bigip"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const restDownloadPath = "/var/config/rest/downloads"

// pkcs12InstallRequest is the body for the iControl REST sys/crypto/pkcs12 install command.
type pkcs12InstallRequest struct {
	Command       string `json:"command"`
	Name          string `json:"name,omitempty"`
	Partition     string `json:"partition,omitempty"`
	FromLocalFile string `json:"fromLocalFile,omitempty"`
	Passphrase    string `json:"passphrase,omitempty"`
}

// installPKCS12 uploads raw PKCS12 bytes to BIG-IP and runs the install command.
// The key will be stored passphrase-protected when passphrase is non-empty.
// After installation BIG-IP creates <partition>/<name>.crt and <partition>/<name>.key.
func installPKCS12(client *bigip.BigIP, name, partition string, p12Data []byte, passphrase string) error {
	filename := name + ".crt"

	log.Printf("[DEBUG] installPKCS12: p12Data size=%d", len(p12Data))

	// 1. Delete any leftover temp b64 file
	b64Filename := filename + ".b64"
	client.RunCommand(&bigip.BigipCommand{
		Command:     "run",
		UtilCmdArgs: fmt.Sprintf("-c \"rm -f %s/%s\"", restDownloadPath, b64Filename),
	})

	// 2. Upload Base64 representation in chunks
	b64Data := base64.StdEncoding.EncodeToString(p12Data)
	chunkSize := 1024
	for i := 0; i < len(b64Data); i += chunkSize {
		end := i + chunkSize
		if end > len(b64Data) {
			end = len(b64Data)
		}
		chunk := b64Data[i:end]
		cmdReq := &bigip.BigipCommand{
			Command:     "run",
			UtilCmdArgs: fmt.Sprintf("-c \"printf '%%s' '%s' >> %s/%s\"", chunk, restDownloadPath, b64Filename),
		}
		if _, err := client.RunCommand(cmdReq); err != nil {
			return fmt.Errorf("error writing base64 chunk to %s: %w", b64Filename, err)
		}
	}

	// 3. Decode the appended base64 file to the target cert file
	cmdReq := &bigip.BigipCommand{
		Command:     "run",
		UtilCmdArgs: fmt.Sprintf("-c \"fold -w 76 %s/%s | base64 -d > %s/%s\"", restDownloadPath, b64Filename, restDownloadPath, filename),
	}
	if _, err := client.RunCommand(cmdReq); err != nil {
		return fmt.Errorf("error decoding complete base64 file %s: %w", filename, err)
	}

	// 4. Cleanup the temp base64 file
	client.RunCommand(&bigip.BigipCommand{
		Command:     "run",
		UtilCmdArgs: fmt.Sprintf("-c \"rm -f %s/%s\"", restDownloadPath, b64Filename),
	})

	req := &pkcs12InstallRequest{
		Command:       "install",
		Name:          name,
		Partition:     partition,
		FromLocalFile: restDownloadPath + "/" + filename,
		Passphrase:    passphrase,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("error serializing PKCS12 install request: %w", err)
	}

	apiReq := &bigip.APIRequest{
		Method:      "post",
		URL:         "sys/crypto/pkcs12",
		Body:        string(body),
		ContentType: "application/json",
	}
	if _, err := client.APICall(apiReq); err != nil {
		return fmt.Errorf("error running PKCS12 install command for %s: %w", name, err)
	}
	return nil
}

func resourceBigipSSLPKCS12() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceBigipSSLPKCS12Create,
		ReadContext:   resourceBigipSSLPKCS12Read,
		UpdateContext: resourceBigipSSLPKCS12Update,
		DeleteContext: resourceBigipSSLPKCS12Delete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Base name for the certificate and key. BIG-IP creates <name>.crt and <name>.key.",
			},
			"partition": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "Common",
				Description:  "BIG-IP partition.",
				ValidateFunc: validatePartitionName,
			},
			"p12_content_wo": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Base64-encoded PKCS12 bundle (certificate + key) - Write Only.",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return !d.HasChange("p12_content_wo_version")
				},
			},
			"p12_content_wo_version": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Version of the PKCS12 bundle. Increment to trigger re-import.",
			},
			"passphrase_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "Passphrase protecting the PKCS12 bundle - Write Only. The key will be stored passphrase-protected on BIG-IP.",
				RequiredWith: []string{"passphrase_wo_version"},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return !d.HasChange("passphrase_wo_version")
				},
			},
			"passphrase_wo_version": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "",
				Description:  "Version of the passphrase - Write Only.",
				RequiredWith: []string{"passphrase_wo"},
			},
			"issuer_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Full path of the issuer (CA) certificate to associate, e.g. /Common/ca-bundle.crt.",
			},
			"cert_full_path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path of the installed certificate on BIG-IP, e.g. /Common/<name>.crt.",
			},
			"key_full_path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path of the installed key on BIG-IP, e.g. /Common/<name>.key.",
			},
		},
	}
}

func resourceBigipSSLPKCS12Create(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)

	name := d.Get("name").(string)
	partition := d.Get("partition").(string)
	p12B64 := d.Get("p12_content_wo").(string)
	passphrase := d.Get("passphrase_wo").(string)

	p12Bytes, err := base64.StdEncoding.DecodeString(p12B64)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error decoding p12_content_wo as base64: %w", err))
	}

	log.Printf("[INFO] Installing PKCS12 bundle as /%s/%s on BIG-IP", partition, name)
	if err := installPKCS12(client, name, partition, p12Bytes, passphrase); err != nil {
		return diag.FromErr(err)
	}

	if val, ok := d.GetOk("issuer_cert"); ok {
		certFullPath := fmt.Sprintf("/%s/%s.crt", partition, name)
		cert := &bigip.Certificate{
			Name:       name + ".crt",
			Partition:  partition,
			IssuerCert: val.(string),
		}
		if err := client.ModifyCertificate(certFullPath, cert); err != nil {
			return diag.FromErr(fmt.Errorf("error setting issuer_cert on %s: %w", certFullPath, err))
		}
	}

	d.SetId(fmt.Sprintf("/%s/%s", partition, name))
	return resourceBigipSSLPKCS12Read(ctx, d, meta)
}

func resourceBigipSSLPKCS12Read(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)

	name := d.Get("name").(string)
	partition := d.Get("partition").(string)

	// On import only the ID is set; parse /<partition>/<name> to restore individual attrs.
	if name == "" {
		id := d.Id()
		parts := strings.SplitN(strings.TrimPrefix(id, "/"), "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return diag.Errorf("invalid import ID %q: expected /<partition>/<name>", id)
		}
		partition = parts[0]
		name = parts[1]
		_ = d.Set("name", name)
		_ = d.Set("partition", partition)
	}

	certFullPath := fmt.Sprintf("/%s/%s.crt", partition, name)
	keyFullPath := fmt.Sprintf("/%s/%s.key", partition, name)

	cert, err := client.GetCertificate(certFullPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading certificate %s: %w", certFullPath, err))
	}
	if cert == nil {
		log.Printf("[WARN] Certificate %s not found, removing from state", certFullPath)
		d.SetId("")
		return nil
	}

	key, err := client.GetKey(keyFullPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading key %s: %w", keyFullPath, err))
	}
	if key == nil {
		log.Printf("[WARN] Key %s not found, removing from state", keyFullPath)
		d.SetId("")
		return nil
	}

	_ = d.Set("cert_full_path", cert.FullPath)
	_ = d.Set("key_full_path", key.FullPath)
	_ = d.Set("partition", cert.Partition)
	_ = d.Set("issuer_cert", cert.IssuerCert)

	return nil
}

func resourceBigipSSLPKCS12Update(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)

	name := d.Get("name").(string)
	partition := d.Get("partition").(string)

	if d.HasChange("p12_content_wo_version") || d.HasChange("passphrase_wo_version") {
		p12B64 := d.Get("p12_content_wo").(string)
		passphrase := d.Get("passphrase_wo").(string)

		p12Bytes, err := base64.StdEncoding.DecodeString(p12B64)
		if err != nil {
			return diag.FromErr(fmt.Errorf("error decoding p12_content_wo as base64: %w", err))
		}

		log.Printf("[INFO] Re-installing PKCS12 bundle /%s/%s on BIG-IP", partition, name)
		if err := installPKCS12(client, name, partition, p12Bytes, passphrase); err != nil {
			return diag.FromErr(err)
		}
	}

	if d.HasChange("issuer_cert") {
		certFullPath := fmt.Sprintf("/%s/%s.crt", partition, name)
		cert := &bigip.Certificate{
			Name:      name + ".crt",
			Partition: partition,
		}
		if val, ok := d.GetOk("issuer_cert"); ok {
			cert.IssuerCert = val.(string)
		}
		if err := client.ModifyCertificate(certFullPath, cert); err != nil {
			return diag.FromErr(fmt.Errorf("error updating issuer_cert on %s: %w", certFullPath, err))
		}
	}

	return resourceBigipSSLPKCS12Read(ctx, d, meta)
}

func resourceBigipSSLPKCS12Delete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*bigip.BigIP)

	name := d.Get("name").(string)
	partition := d.Get("partition").(string)
	keyFullPath := fmt.Sprintf("/%s/%s.key", partition, name)
	certFullPath := fmt.Sprintf("/%s/%s.crt", partition, name)

	log.Printf("[INFO] Deleting PKCS12 key %s and certificate %s", keyFullPath, certFullPath)

	mutex.Lock()
	defer mutex.Unlock()
	t, err := client.StartTransaction()
	if err != nil {
		return diag.FromErr(fmt.Errorf("error starting transaction: %w", err))
	}

	if err := client.DeleteKey(keyFullPath); err != nil {
		log.Printf("[ERROR] unable to delete key %s: %v", keyFullPath, err)
	}
	if err := client.DeleteCertificate(certFullPath); err != nil {
		log.Printf("[ERROR] unable to delete certificate %s: %v", certFullPath, err)
	}

	if err := client.CommitTransaction(t.TransID); err != nil {
		return diag.FromErr(fmt.Errorf("error committing delete transaction: %w", err))
	}

	d.SetId("")
	return nil
}
