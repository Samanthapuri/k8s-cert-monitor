package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"time"
        "encoding/base64"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)
type Conf struct {
	APIVersion string `yaml:"apiVersion"`
	Clusters   []struct {
		Cluster struct {
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			Server                   string `yaml:"server"`
		} `yaml:"cluster"`
		Name string `yaml:"name"`
	} `yaml:"clusters"`
	Contexts []struct {
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
		Name string `yaml:"name"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
	Kind           string `yaml:"kind"`
	Preferences    struct {
	} `yaml:"preferences"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}
func main() {
	apiserverCertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "apiserver_certificate_days_to_expiry",
		Help: "Number of days for apiserver certificate to expiry.",
	})
	kubeCACertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kube_ca_certificate_days_to_expiry",
		Help: "Number of days for ca certificate to expiry.",
	})
	apiserverKubeletClientCertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "apiserver_kubelet_client_certificate_days_to_expiry",
		Help: "Number of days for apiserver kubelet client certificate to expiry.",
	})
	frontProxyClientCertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "front_proxy_client_certificate_days_to_expiry",
		Help: "Number of days for front proxy client certificate to expiry.",
	})
	frontProxyCACertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "front_proxy_ca_certificate_days_to_expiry",
		Help: "Number of days for front proxy ca certificate to expiry.",
	})
	adminConfCertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "admin_conf_certificate_days_to_expiry",
		Help: "Number of days for admin.conf certificate to expiry.",
	})
	schedulerConfCertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "scheduler_conf_certificate_days_to_expiry",
		Help: "Number of days for scheduler.conf certificate expiry.",
	})
	controllerManagerConfCertificateDaysToExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "controller_manager_conf_certificate_days_to_expiry",
		Help: "Number of days for controller-manager.conf certificate expiry.",
	})
	// Create non-global registry.
	registry := prometheus.NewRegistry()

	// Add go runtime metrics and process collectors.
	registry.MustRegister(
		apiserverCertificateDaysToExpiry,
		kubeCACertificateDaysToExpiry,
		apiserverKubeletClientCertificateDaysToExpiry,
		frontProxyClientCertificateDaysToExpiry,
		frontProxyCACertificateDaysToExpiry,
		adminConfCertificateDaysToExpiry,
		schedulerConfCertificateDaysToExpiry,
		controllerManagerConfCertificateDaysToExpiry,
	)

	go func() {
		for {
			//apiserver certificate
			data, _ := os.ReadFile("/etc/kubernetes/pki/apiserver.crt")
			data1, _ := pem.Decode(data)
			crt, err := x509.ParseCertificate([]byte(data1.Bytes))
			if err != nil {
				fmt.Println(err)
			}
			now := time.Now()
			expiry := crt.NotAfter
			duration := expiry.Sub(now)
			days := math.Round(duration.Hours()) / 24
			apiserverCertificateDaysToExpiry.Set(days)

			//kubernetes ca certificate expiry
			data, _ = os.ReadFile("/etc/kubernetes/pki/ca.crt")
			data1, _ = pem.Decode(data)
			crt, err = x509.ParseCertificate([]byte(data1.Bytes))
			if err != nil {
				fmt.Println(err)
			}
			now = time.Now()
			expiry = crt.NotAfter
			duration = expiry.Sub(now)
			days = math.Round(duration.Hours()) / 24
			kubeCACertificateDaysToExpiry.Set(days)

			//front proxy ca certificate expiry
			data, _ = os.ReadFile("/etc/kubernetes/pki/front-proxy-ca.crt")
			data1, _ = pem.Decode(data)
			crt, err = x509.ParseCertificate([]byte(data1.Bytes))
			if err != nil {
				fmt.Println(err)
			}
			now = time.Now()
			expiry = crt.NotAfter
			duration = expiry.Sub(now)
			days = math.Round(duration.Hours()) / 24
			frontProxyCACertificateDaysToExpiry.Set(days)

			//front proxy clinet certificate expiry
			data, _ = os.ReadFile("/etc/kubernetes/pki/front-proxy-client.crt")
			data1, _ = pem.Decode(data)
			crt, err = x509.ParseCertificate([]byte(data1.Bytes))
			if err != nil {
				fmt.Println(err)
			}
			now = time.Now()
			expiry = crt.NotAfter
			duration = expiry.Sub(now)
			days = math.Round(duration.Hours()) / 24
			frontProxyClientCertificateDaysToExpiry.Set(days)

			//scheduleri.conf clinet certificate expiry
			yamlfile, err := os.ReadFile("/etc/kubernetes/scheduler.conf")
                        if err != nil {
                        fmt.Println(err)
                        }
			var conf Conf
			err = yaml.Unmarshal(yamlfile, &conf)
                        if err != nil {
                        fmt.Println(err)
                        }
                        str := conf.Users[0].User.ClientCertificateData
                        dst := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
                        n, err := base64.StdEncoding.Decode(dst, []byte(str))
                        if err != nil {
		            fmt.Println("decode error:", err)
		            return
	                }
	                data = dst[:n]
			data1, _ = pem.Decode(data)
			crt, err = x509.ParseCertificate([]byte(data1.Bytes))
			if err != nil {
				fmt.Println(err)
			}
			now = time.Now()
			expiry = crt.NotAfter
			duration = expiry.Sub(now)
			days = math.Round(duration.Hours()) / 24
			schedulerConfCertificateDaysToExpiry.Set(days)

                        //amdin.conf certificate expiry
                        yamlfile, err = os.ReadFile("/etc/kubernetes/admin.conf")
                        if err != nil {
                        fmt.Println(err)
                        }
                        err = yaml.Unmarshal(yamlfile, &conf)
                        if err != nil {
                        fmt.Println(err)
                        }
                        str = conf.Users[0].User.ClientCertificateData
                        dst = make([]byte, base64.StdEncoding.DecodedLen(len(str)))
                        n, err = base64.StdEncoding.Decode(dst, []byte(str))
                        if err != nil {
                            fmt.Println("decode error:", err)
                            return
                        }
                        data = dst[:n]
                        data1, _ = pem.Decode(data)
                        crt, err = x509.ParseCertificate([]byte(data1.Bytes))
                        if err != nil {
                                fmt.Println(err)
                        }
                        now = time.Now()
                        expiry = crt.NotAfter
                        duration = expiry.Sub(now)
                        days = math.Round(duration.Hours()) / 24
                        adminConfCertificateDaysToExpiry.Set(days)


                        //controller-manager.conf certificate expiry
                        yamlfile, err = os.ReadFile("/etc/kubernetes/controller-manager.conf")
                        if err != nil {
                        fmt.Println(err)
                        }
                        err = yaml.Unmarshal(yamlfile, &conf)
                        if err != nil {
                        fmt.Println(err)
                        }
                        str = conf.Users[0].User.ClientCertificateData
                        dst = make([]byte, base64.StdEncoding.DecodedLen(len(str)))
                        n, err = base64.StdEncoding.Decode(dst, []byte(str))
                        if err != nil {
                            fmt.Println("decode error:", err)
                            return
                        }
                        data = dst[:n]
                        data1, _ = pem.Decode(data)
                        crt, err = x509.ParseCertificate([]byte(data1.Bytes))
                        if err != nil {
                                fmt.Println(err)
                        }
                        now = time.Now()
                        expiry = crt.NotAfter
                        duration = expiry.Sub(now)
                        days = math.Round(duration.Hours()) / 24
                        controllerManagerConfCertificateDaysToExpiry.Set(days)

		}
	}()

	// Expose /metrics HTTP endpoint using the created custom registry.
	http.Handle(
		"/metrics", promhttp.HandlerFor(
			registry,
			promhttp.HandlerOpts{
				EnableOpenMetrics: true,
			}),
	)
	// To test: curl -H 'Accept: application/openmetrics-text' localhost:8080/metrics
	log.Fatalln(http.ListenAndServe(":8080", nil))
}
