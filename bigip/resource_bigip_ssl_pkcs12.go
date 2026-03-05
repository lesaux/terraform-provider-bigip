package bigip

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

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

// uploadResponse is the JSON body returned by /mgmt/shared/file-transfer/uploads on success.
type uploadResponse struct {
	LocalFilePath     string `json:"localFilePath"`
	TemporaryFilePath string `json:"temporaryFilePath"`
	RemainingByteCount int64 `json:"remainingByteCount"`
	TotalByteCount    int64  `json:"totalByteCount"`
}

// uploadP12File uploads raw PKCS12 bytes to the BIG-IP file-transfer endpoint
// using plain byte-slice chunking with Content-Range headers.
//
// Returns the localFilePath reported by BIG-IP in its upload response, which is
// the path that must be passed to the sys/crypto/pkcs12 install command.
//
// This avoids go-bigip's Upload/UploadBytes helper which uses io.Reader.Read()
// and historically treated (n, io.EOF) — the normal "last chunk" response from
// bytes.NewReader — as a fatal error. By slicing []byte directly we never touch
// io.Reader and the EOF problem cannot occur.
func uploadP12File(client *bigip.BigIP, data []byte, filename string) (string, error) {
	const chunkSize = 512 * 1024 // 512 KiB — same as go-bigip default

	size := int64(len(data))
	uploadURL := fmt.Sprintf("%s/mgmt/shared/file-transfer/uploads/%s", client.Host, filename)

	log.Printf("[DEBUG] uploadP12File: uploading %d bytes to %s", size, uploadURL)

	timeout := 60 * time.Second
	if client.ConfigOptions != nil && client.ConfigOptions.APICallTimeout > 0 {
		timeout = client.ConfigOptions.APICallTimeout
	}
	httpClient := &http.Client{
		Transport: client.Transport,
		Timeout:   timeout,
	}

	var lastBody []byte
	for start := int64(0); start < size; {
		end := start + chunkSize
		if end > size {
			end = size
		}

		req, err := http.NewRequest("POST", uploadURL, bytes.NewReader(data[start:end]))
		if err != nil {
			return "", fmt.Errorf("error creating upload request for chunk %d-%d: %w", start, end-1, err)
		}
		if client.Token != "" {
			req.Header.Set("X-F5-Auth-Token", client.Token)
		} else {
			req.SetBasicAuth(client.User, client.Password)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Range", fmt.Sprintf("%d-%d/%d", start, end-1, size))

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("error uploading PKCS12 chunk %d-%d: %w", start, end-1, err)
		}
		lastBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return "", fmt.Errorf("BIG-IP returned HTTP %d for chunk %d-%d: %s", resp.StatusCode, start, end-1, string(lastBody))
		}

		log.Printf("[DEBUG] uploadP12File: uploaded bytes %d-%d/%d, response: %s", start, end-1, size, string(lastBody))
		start = end
	}

	// Parse the final response to get the path where BIG-IP stored the file.
	var uploadResp uploadResponse
	if err := json.Unmarshal(lastBody, &uploadResp); err != nil || uploadResp.LocalFilePath == "" {
		// Fall back to the well-known default path if the response can't be parsed.
		fallback := restDownloadPath + "/" + filename
		log.Printf("[DEBUG] uploadP12File: could not parse localFilePath from response (%v), using fallback: %s", err, fallback)
		return fallback, nil
	}
	log.Printf("[DEBUG] uploadP12File: F5 localFilePath = %s", uploadResp.LocalFilePath)
	return uploadResp.LocalFilePath, nil
}

// installPKCS12 uploads raw PKCS12 bytes to BIG-IP and runs the install command.
// This mirrors what the F5 Ansible bigip_ssl_pkcs12 module does:
// 1. Upload the raw binary .p12 via the file-transfer REST endpoint.
// 2. POST to sys/crypto/pkcs12 to install it from the uploaded local file.
func installPKCS12(client *bigip.BigIP, name, partition string, p12Data []byte, passphrase string) error {
	filename := name + ".p12"

	log.Printf("[DEBUG] installPKCS12: uploading %s (%d bytes)", filename, len(p12Data))

	localFilePath, err := uploadP12File(client, p12Data, filename)
	if err != nil {
		return fmt.Errorf("error uploading PKCS12 file %s: %w", filename, err)
	}

	log.Printf("[DEBUG] installPKCS12: running install from %s", localFilePath)

	req := &pkcs12InstallRequest{
		Command:       "install",
		Name:          name,
		Partition:     partition,
		FromLocalFile: localFilePath,
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
