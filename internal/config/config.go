package config

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level RAVEN configuration, mapping 1:1 to raven.yaml.
type Config struct {
	BMP         BMPConfig         `mapstructure:"bmp"`
	API         APIConfig         `mapstructure:"api"`
	RTR         RTRConfig         `mapstructure:"rtr"`
	Validation  ValidationConfig  `mapstructure:"validation"`
	Outputs     OutputsConfig     `mapstructure:"outputs"`
	Logging     LoggingConfig     `mapstructure:"logging"`
	Events      EventsConfig      `mapstructure:"events"`
	Persistence PersistenceConfig `mapstructure:"persistence"`
	External    ExternalConfig    `mapstructure:"external"`
	Debug       DebugConfig       `mapstructure:"debug"`
}

// DebugConfig holds operator diagnostics. Everything here defaults to off.
type DebugConfig struct {
	Pprof PprofConfig `mapstructure:"pprof"`
}

// PprofConfig configures the runtime profiling endpoint.
type PprofConfig struct {
	// Listen is the address the pprof HTTP server binds to, e.g.
	// "localhost:6060". Empty (the default) disables it entirely. It is a
	// separate listener from the API and metrics servers so that it can be
	// kept on loopback while those are exposed.
	Listen string `mapstructure:"listen"`
}

// ExternalConfig configures correlation against third-party routing data
// sources. Every provider here defaults to disabled.
type ExternalConfig struct {
	RIPEstat RIPEstatConfig `mapstructure:"ripestat"`
}

// RIPEstatConfig configures the RIPEstat looking-glass provider used for
// on-demand global BGP visibility correlation.
type RIPEstatConfig struct {
	// Enabled must be true for the Event Engine's global-correlate action to
	// query RIPEstat. Defaults to false so existing deployments are
	// unaffected without an explicit opt-in.
	//
	// It does not gate `raven check global`: typing that command is itself
	// the opt-in, and it reads the settings below either way.
	Enabled bool `mapstructure:"enabled"`
	// BaseURL is the RIPEstat origin, without the data-call path.
	// Default: https://stat.ripe.net
	BaseURL string `mapstructure:"base-url"`
	// Timeout bounds a single looking-glass query. Default: 5s
	Timeout time.Duration `mapstructure:"timeout"`
	// CacheTTL is how long a per-prefix result stays usable, so a flapping
	// route does not re-query RIPEstat on every event. Default: 60s
	CacheTTL time.Duration `mapstructure:"cache-ttl"`
	// RateLimitPerMin is the per-instance lookup budget per minute, a
	// good-citizen safeguard against hammering RIPEstat. Default: 10
	RateLimitPerMin int `mapstructure:"rate-limit-per-min"`
}

// PersistenceConfig controls warm-start snapshot behaviour.
type PersistenceConfig struct {
	// Enabled must be true to write/read snapshots. Defaults to false
	// so existing deployments are unaffected.
	Enabled bool `mapstructure:"enabled"`
	// SnapshotDir is the directory for snapshot files.
	// Supports ~ expansion. Default: ~/.raven/snapshots
	SnapshotDir string `mapstructure:"snapshot_dir"`
	// StaleEvictionTimeout is how long to wait after startup before
	// evicting routes that were restored from a snapshot but never
	// confirmed by a live BMP message.
	StaleEvictionTimeout time.Duration `mapstructure:"stale_eviction_timeout"`
}

// EventsConfig configures the Phase 3 active-response event engine.
type EventsConfig struct {
	Rules []RuleConfig `mapstructure:"rules"`
	// RTRBulkThreshold is the RTR bulk guard: an RTR update that changes
	// the posture of more routes than this is reported as one
	// rtr_bulk_change event, and its per-route actions are not run. 0
	// (unset) is the default, 100; a negative value disables the guard.
	RTRBulkThreshold int `mapstructure:"rtr-bulk-threshold"`
}

// RuleConfig is the YAML representation of a single event rule.
type RuleConfig struct {
	Name    string        `mapstructure:"name"`
	Trigger TriggerConfig `mapstructure:"trigger"`
	// Cooldown is a Go duration string (e.g. "60s", "5m"). Empty means no cooldown.
	Cooldown string         `mapstructure:"cooldown"`
	Actions  []ActionConfig `mapstructure:"actions"`
}

// TriggerConfig is the YAML representation of a trigger.
// The Type field selects the trigger kind: posture, posture_change, prefix,
// asn, protected_asn, cache_unhealthy, rib, source, rtr_bulk_change, or
// compound.
type TriggerConfig struct {
	Type     string   `mapstructure:"type"`
	Postures []string `mapstructure:"postures"`
	// RIBs is used by the rib trigger: RIB names, adj-rib-in-pre (or
	// pre-policy), adj-rib-in-post (or post-policy), loc-rib, ...
	RIBs   []string `mapstructure:"ribs"`
	Prefix string   `mapstructure:"prefix"`
	ASNs   []uint32 `mapstructure:"asns"`
	// ASNMatch controls how the asn trigger matches: "origin" (default) checks
	// only the last ASN in the AS path; "path" matches any ASN in the full path.
	ASNMatch string `mapstructure:"asn_match"`
	// Sources is used by the source trigger: "bmp", "rtr" or both.
	Sources []string `mapstructure:"sources"`
	// Operator is used by compound triggers: "and" or "or".
	Operator string `mapstructure:"operator"`
	// Triggers holds sub-triggers for compound triggers.
	Triggers []TriggerConfig `mapstructure:"triggers"`
}

// ActionConfig is the YAML representation of an action.
// The Type field selects the action kind: log, webhook, or flowspec.
type ActionConfig struct {
	Type string `mapstructure:"type"`
	// Level is used by the log action: "info", "warn", or "error".
	Level string `mapstructure:"level"`
	// URL is used by the webhook action.
	URL string `mapstructure:"url"`
	// Secret enables HMAC-SHA256 signing for the webhook action.
	Secret string `mapstructure:"secret"`
	// Timeout is a Go duration string for the per-attempt HTTP timeout (webhook action).
	Timeout string `mapstructure:"timeout"`
	// MaxAttempts is the maximum number of delivery attempts (webhook action).
	MaxAttempts int `mapstructure:"max_attempts"`
	// Headers are additional HTTP headers to include in webhook requests.
	Headers map[string]string `mapstructure:"headers"`
	// DryRun is used by the flowspec action to suppress GoBGP injection.
	DryRun bool `mapstructure:"dry_run"`
	// GoBGPAddress is the GoBGP gRPC management endpoint for the flowspec action.
	GoBGPAddress string `mapstructure:"gobgp_address"`
	// MaxRules is the maximum number of concurrently active flowspec rules.
	MaxRules int `mapstructure:"max_rules"`
	// TTL is a Go duration string for the per-rule lifetime (flowspec action).
	TTL string `mapstructure:"ttl"`
	// RuleAction is the Flowspec traffic action: "drop" or "rate-limit".
	RuleAction string `mapstructure:"rule_action"`
	// ReaperInterval is a Go duration string for the flowspec rule reaper cadence.
	ReaperInterval string `mapstructure:"reaper_interval"`
	// ApprovalWebhook is an optional URL for flowspec injection approval.
	ApprovalWebhook string `mapstructure:"approval_webhook"`
	// ApprovalTimeout is a Go duration string for the approval webhook HTTP timeout.
	ApprovalTimeout string `mapstructure:"approval_timeout"`
	// CacheTTL is a Go duration string used by the global-correlate action
	// as its freshness requirement: a cached provider result younger than
	// this is reused instead of re-querying. Empty falls back to
	// external.ripestat.cache-ttl.
	CacheTTL string `mapstructure:"cache_ttl"`
}

// WebhookActionConfig collects the webhook-specific fields from ActionConfig.
// It is populated by buildAction in the events package.
type WebhookActionConfig struct {
	URL         string            `mapstructure:"url"`
	Secret      string            `mapstructure:"secret"`
	Timeout     string            `mapstructure:"timeout"`
	MaxAttempts int               `mapstructure:"max_attempts"`
	Headers     map[string]string `mapstructure:"headers"`
}

// FlowspecActionConfig collects the flowspec-specific fields from ActionConfig.
// It is populated by buildAction in the events package.
type FlowspecActionConfig struct {
	// GoBGPAddress is the GoBGP gRPC management endpoint. When empty, no GoBGP
	// client is created and live injection is unavailable.
	GoBGPAddress string `mapstructure:"gobgp_address"`
	// MaxRules is the maximum number of concurrently active rules (default 100; 0 = unlimited).
	MaxRules int `mapstructure:"max_rules"`
	// TTL is a Go duration string for the per-rule lifetime (default "1h").
	TTL string `mapstructure:"ttl"`
	// RuleAction is the Flowspec action: "drop" or "rate-limit" (default "drop").
	RuleAction string `mapstructure:"rule_action"`
	// DryRun logs rules without injecting them into GoBGP.
	DryRun bool `mapstructure:"dry_run"`
	// ReaperInterval is a Go duration string for how often expired rules are withdrawn (default "30s").
	ReaperInterval string `mapstructure:"reaper_interval"`
	// ApprovalWebhook is an optional URL to POST for injection approval.
	ApprovalWebhook string `mapstructure:"approval_webhook"`
	// ApprovalTimeout is a Go duration string for the approval webhook HTTP timeout (default "10s").
	ApprovalTimeout string `mapstructure:"approval_timeout"`
}

type BMPConfig struct {
	Listen string       `mapstructure:"listen"`
	TLS    *TLSConfig   `mapstructure:"tls"`   // nil = plain TCP (default)
	Kafka  *KafkaIngest `mapstructure:"kafka"` // Phase 4 — nil means embedded BMP receiver
	// AllowedRouters lists the addresses and prefixes BMP connections are
	// accepted from; empty allows any source. See ParseAllowedRouters.
	AllowedRouters []string `mapstructure:"allowed-routers"`
}

// APIConfig configures the HTTP API the CLI talks to.
type APIConfig struct {
	// Listen is the API's bind address. The default, 127.0.0.1:11020,
	// serves only this host; set it to expose the API.
	Listen string `mapstructure:"listen"`
}

// DefaultAPIListen is the API's bind address when api.listen is not set.
const DefaultAPIListen = "127.0.0.1:11020"

// ParseAllowedRouters parses bmp.allowed-routers entries: an IP address
// (a single host) or a prefix, IPv4 or IPv6. IPv4-mapped IPv6 entries are
// taken as IPv4, as BMP source addresses are; host bits in a prefix are
// ignored.
func ParseAllowedRouters(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for i, e := range entries {
		var p netip.Prefix
		if a, err := netip.ParseAddr(e); err == nil {
			if a.Zone() != "" {
				return nil, fmt.Errorf("bmp.allowed-routers[%d]: %q: zones are not supported", i, e)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		} else if p, err = netip.ParsePrefix(e); err != nil {
			return nil, fmt.Errorf("bmp.allowed-routers[%d]: %q is not an IP address or prefix", i, e)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("bmp.allowed-routers[%d]: %q: an IPv4-mapped prefix must be /96 or longer", i, e)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

type KafkaIngest struct {
	Brokers []string `mapstructure:"brokers"`
	Topic   string   `mapstructure:"topic"`
	Group   string   `mapstructure:"group"`
}

type RTRConfig struct {
	Caches         []RTRCacheConfig `mapstructure:"caches"`
	RTRVersion     string           `mapstructure:"rtr-version"`     // "auto", "0", "1", "2"
	ExpireInterval int              `mapstructure:"expire-interval"` // seconds, 0 = use cache default
	// VersionReprobeInterval is how often a client that a cache made
	// downgrade (Error Report code 4) checks whether the cache now supports
	// the configured version.
	VersionReprobeInterval time.Duration `mapstructure:"version-reprobe-interval"`
}

type RTRCacheConfig struct {
	Address    string     `mapstructure:"address"`
	Preference int        `mapstructure:"preference"`
	Transport  string     `mapstructure:"transport"` // "tcp", "tls", "ssh"
	TLS        *TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	CA   string `mapstructure:"ca"`
	Cert string `mapstructure:"cert"`
	Key  string `mapstructure:"key"`
	// MinVersion locks the minimum negotiated TLS version: "1.2" or "1.3".
	// Empty (or absent) defaults to "1.2" so existing deployments are unaffected.
	MinVersion string `mapstructure:"tls-min-version"`
}

// TLSMinVersion resolves the configured minimum TLS version to a crypto/tls
// constant. Anything other than "1.3" (including empty or a nil receiver)
// resolves to TLS 1.2, preserving the historical default.
func (t *TLSConfig) TLSMinVersion() uint16 {
	if t != nil && t.MinVersion == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

type ValidationConfig struct {
	ROV                  bool   `mapstructure:"rov"`
	ASPA                 bool   `mapstructure:"aspa"`
	ASPADefaultProcedure string `mapstructure:"aspa-default-procedure"` // "upstream", "downstream", "auto"
	ASPAASSetBehavior    string `mapstructure:"aspa-as-set-behavior"`   // "unverifiable", "best-effort"
	// ASPAPeers sets the ASPA procedure per BMP peer from the neighbor's role.
	ASPAPeers []ASPAPeer `mapstructure:"aspa-peers"`
}

// ASPAPeer maps one BMP peer, by address or by ASN, to its role.
type ASPAPeer struct {
	Address string `mapstructure:"address"` // BMP peer address
	ASN     uint32 `mapstructure:"asn"`     // peer ASN
	// NeighborRole is the neighbor's relationship to the monitored router:
	// "provider", "customer", "peer", "rs" or "rs-client".
	NeighborRole string `mapstructure:"neighbor-role"`
}

// ParsedAddress returns the entry's address, unmapped so that it compares
// equal to the IPv4 peer addresses BMP produces.
func (p ASPAPeer) ParsedAddress() (netip.Addr, error) {
	a, err := netip.ParseAddr(p.Address)
	return a.Unmap(), err
}

// validNeighborRoles are the accepted aspa-peers neighbor-role values.
var validNeighborRoles = map[string]bool{
	"provider": true, "customer": true, "peer": true, "rs": true, "rs-client": true,
}

type OutputsConfig struct {
	Prometheus *PrometheusOutput `mapstructure:"prometheus"`
	Kafka      *KafkaOutput      `mapstructure:"kafka"`
	File       *FileOutput       `mapstructure:"file"`
	OTel       OTelOutputConfig  `mapstructure:"otel"`
}

// OTelOutputConfig is the YAML representation of the OTel output.
// It maps 1:1 to internal/otel.OTelConfig.
type OTelOutputConfig struct {
	Enabled            bool              `mapstructure:"enabled"`
	Endpoint           string            `mapstructure:"endpoint"`
	Protocol           string            `mapstructure:"protocol"`
	Interval           time.Duration     `mapstructure:"interval"`
	Headers            map[string]string `mapstructure:"headers"`
	Insecure           bool              `mapstructure:"insecure"`
	ResourceAttributes map[string]string `mapstructure:"resource_attributes"`
}

type PrometheusOutput struct {
	Listen string `mapstructure:"listen"`
	Path   string `mapstructure:"path"`
}

type KafkaOutput struct {
	Brokers []string `mapstructure:"brokers"`
	Topic   string   `mapstructure:"topic"`
}

type FileOutput struct {
	Path     string `mapstructure:"path"`
	Rotation string `mapstructure:"rotation"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// EnvPrefix is the prefix of every environment variable that overrides a
// config key.
const EnvPrefix = "RAVEN"

// envKeyReplacer maps a config key to its environment variable suffix: both
// the nesting dot and the hyphen in a key become an underscore, so
// validation.aspa-default-procedure is RAVEN_VALIDATION_ASPA_DEFAULT_PROCEDURE.
var envKeyReplacer = strings.NewReplacer(".", "_", "-", "_")

// ConfigureEnv makes RAVEN_* environment variables override config keys.
//
// AutomaticEnv alone is not enough. Without the key replacer viper looks up
// bmp.listen as RAVEN_BMP.LISTEN, a name no shell can export. And
// viper.Unmarshal only fills keys viper already knows about, from the
// config file, a default or a binding, so a key with no default
// (rtr.expire-interval, bmp.tls.ca, ...) would ignore its env var. Binding
// every key of Config explicitly closes that gap.
//
// Keys inside lists (rtr.caches, events.rules) and maps (headers,
// resource_attributes) have no fixed name and cannot be set from the
// environment.
func ConfigureEnv() {
	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(envKeyReplacer)
	viper.AutomaticEnv()
	for _, key := range envKeys(reflect.TypeOf(Config{}), "") {
		// BindEnv with only a key cannot fail.
		_ = viper.BindEnv(key)
	}
}

// envKeys returns the dotted config key of every scalar field reachable from
// struct type t, following nested and pointer-to structs. Lists of structs
// and maps are skipped; see ConfigureEnv.
func envKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Tag.Get("mapstructure")
		if name == "" || name == "-" {
			continue
		}
		key := prefix + name

		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch {
		case ft.Kind() == reflect.Struct:
			keys = append(keys, envKeys(ft, key+".")...)
		case ft.Kind() == reflect.Map,
			ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct:
			// No fixed key to bind.
		default:
			keys = append(keys, key)
		}
	}
	return keys
}

// Load reads the viper-populated config into typed structs and applies defaults.
func Load() (*Config, error) {
	// Defaults
	viper.SetDefault("outputs.otel.enabled", false)
	viper.SetDefault("outputs.otel.endpoint", "localhost:4317")
	viper.SetDefault("outputs.otel.protocol", "grpc")
	viper.SetDefault("outputs.otel.interval", 30*time.Second)
	viper.SetDefault("outputs.otel.insecure", true)
	viper.SetDefault("outputs.otel.resource_attributes", map[string]string{
		"service.name":    "raven",
		"service.version": "v0.1.0",
	})
	viper.SetDefault("persistence.enabled", false)
	viper.SetDefault("persistence.snapshot_dir", "~/.raven/snapshots")
	viper.SetDefault("persistence.stale_eviction_timeout", 5*time.Minute)
	viper.SetDefault("bmp.listen", ":11019")
	viper.SetDefault("api.listen", DefaultAPIListen)
	viper.SetDefault("rtr.rtr-version", "auto")
	viper.SetDefault("events.rtr-bulk-threshold", 100)
	viper.SetDefault("rtr.version-reprobe-interval", time.Hour)
	viper.SetDefault("validation.rov", true)
	viper.SetDefault("validation.aspa", true)
	viper.SetDefault("validation.aspa-default-procedure", "upstream")
	viper.SetDefault("validation.aspa-as-set-behavior", "unverifiable")
	viper.SetDefault("outputs.prometheus.listen", ":9595")
	viper.SetDefault("outputs.prometheus.path", "/metrics")
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("external.ripestat.enabled", false)
	viper.SetDefault("external.ripestat.base-url", "https://stat.ripe.net")
	viper.SetDefault("external.ripestat.timeout", 5*time.Second)
	viper.SetDefault("external.ripestat.cache-ttl", 60*time.Second)
	viper.SetDefault("external.ripestat.rate-limit-per-min", 10)
	viper.SetDefault("debug.pprof.listen", "")

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	// RTR version must be valid
	switch cfg.RTR.RTRVersion {
	case "auto", "0", "1", "2", "":
		// ok
	default:
		return fmt.Errorf("invalid rtr-version %q: must be auto, 0, 1, or 2", cfg.RTR.RTRVersion)
	}

	if _, err := ParseAllowedRouters(cfg.BMP.AllowedRouters); err != nil {
		return err
	}

	// ASPA procedure must be valid
	switch cfg.Validation.ASPADefaultProcedure {
	case "upstream", "downstream", "auto", "":
		// ok
	default:
		return fmt.Errorf("invalid aspa-default-procedure %q", cfg.Validation.ASPADefaultProcedure)
	}

	if err := validateASPAPeers(cfg.Validation.ASPAPeers); err != nil {
		return err
	}

	// ASPA AS_SET behavior must be valid
	switch cfg.Validation.ASPAASSetBehavior {
	case "unverifiable", "best-effort", "":
		// ok
	default:
		return fmt.Errorf("invalid aspa-as-set-behavior %q", cfg.Validation.ASPAASSetBehavior)
	}

	// External provider settings are only validated when the provider is
	// enabled, so a stale or half-filled disabled section cannot break
	// startup.
	if cfg.External.RIPEstat.Enabled {
		rs := cfg.External.RIPEstat
		if u, err := url.Parse(rs.BaseURL); err != nil {
			return fmt.Errorf("invalid external.ripestat.base-url %q: %w", rs.BaseURL, err)
		} else if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("invalid external.ripestat.base-url %q: want an http(s) URL with a host", rs.BaseURL)
		}
		if rs.Timeout < 0 {
			return fmt.Errorf("external.ripestat.timeout must not be negative")
		}
		if rs.CacheTTL < 0 {
			return fmt.Errorf("external.ripestat.cache-ttl must not be negative")
		}
		if rs.RateLimitPerMin < 0 {
			return fmt.Errorf("external.ripestat.rate-limit-per-min must not be negative")
		}
	}

	return nil
}

// validateASPAPeers checks each aspa-peers entry names exactly one of
// address/asn and a valid role, and that no address or ASN repeats.
func validateASPAPeers(peers []ASPAPeer) error {
	addrs := make(map[netip.Addr]bool, len(peers))
	asns := make(map[uint32]bool, len(peers))
	for i, p := range peers {
		hasAddr, hasASN := p.Address != "", p.ASN != 0
		if hasAddr == hasASN {
			return fmt.Errorf("validation.aspa-peers[%d]: set exactly one of address or asn", i)
		}
		if !validNeighborRoles[p.NeighborRole] {
			return fmt.Errorf("validation.aspa-peers[%d]: invalid neighbor-role %q: must be provider, customer, peer, rs or rs-client", i, p.NeighborRole)
		}
		if hasASN {
			if asns[p.ASN] {
				return fmt.Errorf("validation.aspa-peers[%d]: duplicate asn %d", i, p.ASN)
			}
			asns[p.ASN] = true
			continue
		}
		a, err := p.ParsedAddress()
		if err != nil {
			return fmt.Errorf("validation.aspa-peers[%d]: invalid address %q: %w", i, p.Address, err)
		}
		if addrs[a] {
			return fmt.Errorf("validation.aspa-peers[%d]: duplicate address %s", i, a)
		}
		addrs[a] = true
	}
	return nil
}
