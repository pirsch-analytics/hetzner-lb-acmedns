package cert

// CertRequest is the configuration for a certificate request.
type CertRequest struct {
	Email   string  `json:"email"`
	ACMEDNS ACMEDNS `json:"acmedns"`
	Hetzner Hetzner `json:"hetzner"`
}

// ACMEDNS is the configuration for acme-dns.
type ACMEDNS struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	FullDomain string   `json:"full_domain"`
	SubDomain  string   `json:"sub_domain"`
	Domains    []string `json:"domains"`
}

// Hetzner is the configuration for Hetzner.
type Hetzner struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	LBName string            `json:"lb_name"`
	LBPort int               `json:"lb_port"`
}
