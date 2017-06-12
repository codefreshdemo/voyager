package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"appscode.com/ark/pkg/system"
	"github.com/appscode/go/flags"
	"github.com/appscode/log"
	logs "github.com/appscode/log/golog"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func main() {
	defer logs.FlushLogs()

	var rootCmd = &cobra.Command{
		Use: "ark",
		PersistentPreRun: func(c *cobra.Command, args []string) {
			c.Flags().VisitAll(func(flag *pflag.Flag) {
				log.Infof("FLAG: --%s=%q", flag.Name, flag.Value)
			})
		},
	}
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	// ref: https://github.com/kubernetes/kubernetes/issues/17162#issuecomment-225596212
	flag.CommandLine.Parse([]string{})

	logs.InitLogs()

	rootCmd.AddCommand(NewCmdGenerate())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalln(err)
	}
	os.Exit(0)
}

func NewCmdGenerate() *cobra.Command {
	mgr := &CertManager{
		Expiry: 10 * 365 * 24 * time.Hour,
	}
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate certificates for Kubernetes cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.SetLogLevel(4)
			flags.EnsureRequiredFlags(cmd, "folder", "namespace", "cluster", "master-external-ip", "master-internal-ip")

			return mgr.GenClusterCerts()
		},
	}

	cmd.Flags().StringVar(&mgr.Folder, "folder", mgr.Folder, "Folder where certs are stored")
	cmd.Flags().StringArrayVar(&mgr.IPs, "ips", mgr.IPs, "List of ips used as SANs")
	return cmd
}

type CertManager struct {
	Folder string
	Expiry time.Duration
	IPs    []string
}

func (opt *CertManager) certFile(name string) string {
	return fmt.Sprintf("%s/%s.crt", opt.Folder, strings.ToLower(name))
}

func (opt *CertManager) keyFile(name string) string {
	return fmt.Sprintf("%s/%s.key", opt.Folder, strings.ToLower(name))
}

func (opt *CertManager) initCA() error {
	certReq := &csr.CertificateRequest{
		CN: system.ClusterCAName(opt.Namespace, opt.Cluster),
		Hosts: []string{
			"127.0.0.1",
		},
		KeyRequest: csr.NewBasicKeyRequest(),
		CA: &csr.CAConfig{
			PathLength: 2,
			Expiry:     opt.Expiry.String(),
		},
	}

	cert, _, key, err := initca.New(certReq)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(opt.certFile("ca"), cert, 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(opt.keyFile("ca"), key, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (opt *CertManager) createClientCert(csrReq *csr.CertificateRequest) error {
	g := &csr.Generator{Validator: genkey.Validator}
	csrPem, key, err := g.ProcessRequest(csrReq)
	if err != nil {
		return err
	}

	var cfg cli.Config
	cfg.CAKeyFile = opt.keyFile("ca")
	cfg.CAFile = opt.certFile("ca")
	cfg.CFG = &config.Config{
		Signing: &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig(),
		},
	}
	cfg.CFG.Signing.Default.Expiry = opt.Expiry
	cfg.CFG.Signing.Default.ExpiryString = opt.Expiry.String()

	s, err := sign.SignerFromConfig(cfg)
	if err != nil {
		return err
	}
	var cert []byte
	signReq := signer.SignRequest{
		Request: string(csrPem),
		Hosts:   signer.SplitHosts(cfg.Hostname),
		Profile: cfg.Profile,
		Label:   cfg.Label,
	}

	cert, err = s.Sign(signReq)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(opt.certFile(csrReq.CN), cert, 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(opt.keyFile(csrReq.CN), key, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (opt *CertManager) GenClusterCerts() error {
	var csrReq csr.CertificateRequest
	csrReq.KeyRequest = csr.NewBasicKeyRequest()

	err := os.MkdirAll(opt.Folder, 0755)
	if err != nil {
		return err
	}

	////////// Cluster CA //////////
	err = opt.initCA()
	if err != nil {
		return err
	}
	log.Infoln("Created CA cert")
	////////////////////////

	////////// Master ////////////
	csrReq.CN = "voyager"
	csrReq.Hosts = []string{"127.0.0.1"}
	if len(opt.IPs) > 0 {
		csrReq.Hosts = append(csrReq.Hosts, opt.IPs...)
	}

	err = opt.createClientCert(&csrReq)
	if err != nil {
		return err
	}
	log.Infoln("Created client cert")
	//////////////////////////////

	log.Infoln("Certificates generated successfully...")
	return nil
}
