package intent

// Federation maps each SPIFFE trust domain to its cluster and bundle endpoint.
type Federation struct {
	TrustDomains map[string]TrustDomain `json:"trustDomains"`
	AllowReach   []Pair                 `json:"allowReach"`
}

type TrustDomain struct {
	Cluster        string   `json:"cluster"`
	SPIREParent    string   `json:"spireParent"`
	BundleEndpoint string   `json:"bundleEndpoint"`
	Trusts         []string `json:"trusts,omitempty"`
}

func (w Workload) Domain(defaultDomain string) string {
	if w.TrustDomain != "" {
		return w.TrustDomain
	}
	return defaultDomain
}

func (in Intent) Cluster(w Workload) string {
	if in.Federation != nil {
		return in.Federation.TrustDomains[w.Domain(in.TrustDomain)].Cluster
	}
	return ""
}
