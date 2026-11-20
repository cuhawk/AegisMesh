package intent

type ModelClaims struct {
	ModelID      string   `json:"model_id"`
	ToolScopes   []string `json:"tool_scopes"`
	DelegatorSub string   `json:"delegator_sub"`
}

type JWTAuthority struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwksURI"`
}

type HTTPRoute struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Gateway   string `json:"gateway"`
	Listener  string `json:"listener"`
	Hostname  string `json:"hostname"`
	Backend   string `json:"backend"`
	Service   string `json:"service"`
	Port      int    `json:"port"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

type ReferenceGrant struct {
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	FromNamespace string `json:"fromNamespace"`
	Service       string `json:"service"`
}

// IsolationInventory describes existing infrastructure to audit before emission.
type IsolationInventory struct {
	EnvoyAdmins    []EnvoyAdmin    `json:"envoyAdmins,omitempty"`
	TLSSecretSyncs []TLSSecretSync `json:"tlsSecretSyncs,omitempty"`
	ClusterCIDRs   []string        `json:"clusterCIDRs,omitempty"`
	IPBlocks       []IPBlock       `json:"ipBlocks,omitempty"`
}

type EnvoyAdmin struct {
	Workload string `json:"workload"`
	Address  string `json:"address"`
	Isolated bool   `json:"isolated"`
}

type TLSSecretSync struct {
	SourceNamespace string `json:"sourceNamespace"`
	SourceName      string `json:"sourceName"`
	TargetNamespace string `json:"targetNamespace"`
	TargetName      string `json:"targetName"`
}

type IPBlock struct {
	Policy string   `json:"policy"`
	CIDR   string   `json:"cidr"`
	Except []string `json:"except,omitempty"`
}

func (w Workload) Principal(trustDomain string) string {
	return trustDomain + "/ns/" + w.Namespace + "/sa/" + w.ServiceAccount
}

func (w Workload) SPIFFEID(trustDomain string) string {
	return "spiffe://" + w.Principal(trustDomain)
}
