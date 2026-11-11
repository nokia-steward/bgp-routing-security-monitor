package events

import (
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/external"
	"github.com/nokia/bgp-routing-security-monitor/internal/flowspec"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// buildOptions collects optional dependencies injected into BuildEngine.
type buildOptions struct {
	globalVisibility external.GlobalVisibilityProvider
	// defaultCacheTTL is used by global-correlate actions that do not set
	// their own cache_ttl. Zero means the provider's default.
	defaultCacheTTL time.Duration
}

// Option configures BuildEngine.
type Option func(*buildOptions)

// WithGlobalVisibility supplies the provider backing global-correlate
// actions, along with the default freshness requirement from
// external.ripestat.cache-ttl.
//
// Without it, a config that uses a global-correlate action is rejected at
// build time rather than silently producing Inconclusive annotations
// forever.
func WithGlobalVisibility(p external.GlobalVisibilityProvider, defaultCacheTTL time.Duration) Option {
	return func(o *buildOptions) {
		o.globalVisibility = p
		o.defaultCacheTTL = defaultCacheTTL
	}
}

// BuildEngine constructs an Engine from EventsConfig. It also returns every
// flowspec.Manager created for flowspec actions; callers must start each
// manager's Run goroutine scoped to the server context.
// Returns a descriptive error (including the rule name) if any rule fails to parse.
func BuildEngine(cfg config.EventsConfig, logger *slog.Logger, opts ...Option) (*Engine, []*flowspec.Manager, error) {
	var o buildOptions
	for _, opt := range opts {
		opt(&o)
	}

	rules := make([]*Rule, 0, len(cfg.Rules))
	var managers []*flowspec.Manager
	for _, rc := range cfg.Rules {
		rule, ruleManagers, err := buildRule(rc, logger, &o)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %q: %w", rc.Name, err)
		}
		rules = append(rules, rule)
		managers = append(managers, ruleManagers...)
	}
	eng := NewEngine(rules, logger)
	// Unset (0) is the default; a negative threshold disables the guard.
	switch {
	case cfg.RTRBulkThreshold > 0:
		eng.SetRTRBulkThreshold(cfg.RTRBulkThreshold)
	case cfg.RTRBulkThreshold < 0:
		eng.SetRTRBulkThreshold(0)
		logger.Warn("RTR bulk guard disabled (events.rtr-bulk-threshold is negative): "+
			"an RTR update that changes many routes fires every per-route action, FlowSpec included",
			"rtr_bulk_threshold", cfg.RTRBulkThreshold)
	}
	return eng, managers, nil
}

func buildRule(rc config.RuleConfig, logger *slog.Logger, o *buildOptions) (*Rule, []*flowspec.Manager, error) {
	trigger, err := buildTrigger(rc.Trigger)
	if err != nil {
		return nil, nil, fmt.Errorf("trigger: %w", err)
	}

	actions := make([]Action, 0, len(rc.Actions))
	var enrichers []Enricher
	var managers []*flowspec.Manager
	for i, ac := range rc.Actions {
		action, mgr, err := buildAction(ac, rc.Name, logger, o)
		if err != nil {
			return nil, nil, fmt.Errorf("action[%d]: %w", i, err)
		}
		// Enrichers are partitioned out of the concurrent action set so
		// they can run first and annotate the event the actions then see.
		if enricher, ok := action.(Enricher); ok {
			enrichers = append(enrichers, enricher)
			continue
		}
		actions = append(actions, action)
		if mgr != nil {
			managers = append(managers, mgr)
		}
	}

	var cooldown time.Duration
	if rc.Cooldown != "" {
		d, err := time.ParseDuration(rc.Cooldown)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cooldown %q: %w", rc.Cooldown, err)
		}
		cooldown = d
	}

	return &Rule{
		Name:        rc.Name,
		Trigger:     trigger,
		Actions:     actions,
		Enrichers:   enrichers,
		Cooldown:    cooldown,
		log:         logger.With("rule", rc.Name),
		cooldownMap: make(map[string]time.Time),
	}, managers, nil
}

func buildTrigger(tc config.TriggerConfig) (Trigger, error) {
	switch tc.Type {
	case "posture":
		postures, err := parsePostures(tc.Postures)
		if err != nil {
			return nil, err
		}
		return &PostureTrigger{Postures: postures}, nil

	case "posture_change":
		postures, err := parsePostures(tc.Postures)
		if err != nil {
			return nil, err
		}
		return &PostureChangeTrigger{Postures: postures}, nil

	case "prefix":
		if tc.Prefix == "" {
			return nil, fmt.Errorf("prefix trigger requires a non-empty prefix")
		}
		p, err := netip.ParsePrefix(tc.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", tc.Prefix, err)
		}
		return &PrefixTrigger{Supernet: p.Masked()}, nil

	case "asn":
		if len(tc.ASNs) == 0 {
			return nil, fmt.Errorf("asn trigger requires at least one asn")
		}
		match := tc.ASNMatch
		if match == "" {
			match = "origin"
		}
		if match != "origin" && match != "path" {
			return nil, fmt.Errorf("asn trigger asn_match must be \"origin\" or \"path\", got %q", match)
		}
		return &ASNTrigger{ASNs: tc.ASNs, Match: match}, nil

	case "protected_asn":
		if len(tc.ASNs) == 0 {
			return nil, fmt.Errorf("protected_asn trigger requires at least one asn")
		}
		return &ProtectedASNTrigger{ASNs: tc.ASNs}, nil

	case "cache_unhealthy":
		return &CacheUnhealthyTrigger{}, nil

	case "source":
		if len(tc.Sources) == 0 {
			return nil, fmt.Errorf("source trigger requires at least one source")
		}
		for _, src := range tc.Sources {
			if src != SourceBMP && src != SourceRTR {
				return nil, fmt.Errorf("source trigger: unknown source %q (want %q or %q)", src, SourceBMP, SourceRTR)
			}
		}
		return &SourceTrigger{Sources: tc.Sources}, nil

	case "rtr_bulk_change":
		return &RTRBulkChangeTrigger{}, nil

	case "rib":
		if len(tc.RIBs) == 0 {
			return nil, fmt.Errorf("rib trigger requires at least one rib")
		}
		ribs, err := types.ParseRIBSet(tc.RIBs)
		if err != nil {
			return nil, fmt.Errorf("rib trigger: %w", err)
		}
		return &RIBTrigger{RIBs: ribs}, nil

	case "compound":
		if len(tc.Triggers) == 0 {
			return nil, fmt.Errorf("compound trigger requires at least one sub-trigger")
		}
		if tc.Operator != "and" && tc.Operator != "or" {
			return nil, fmt.Errorf("compound operator must be \"and\" or \"or\", got %q", tc.Operator)
		}
		subs := make([]Trigger, 0, len(tc.Triggers))
		for i, sub := range tc.Triggers {
			t, err := buildTrigger(sub)
			if err != nil {
				return nil, fmt.Errorf("sub-trigger[%d]: %w", i, err)
			}
			subs = append(subs, t)
		}
		return &CompoundTrigger{Op: tc.Operator, Triggers: subs}, nil

	default:
		return nil, fmt.Errorf("unknown trigger type %q", tc.Type)
	}
}

// buildAction constructs an Action from ActionConfig. For flowspec actions it
// also returns the Manager that the caller must start (Run). For all other
// action types the returned manager is nil.
func buildAction(ac config.ActionConfig, ruleName string, logger *slog.Logger, o *buildOptions) (Action, *flowspec.Manager, error) {
	switch ac.Type {
	case "log":
		level := ac.Level
		if level == "" {
			level = "info"
		}
		return &LogAction{level: level, log: logger}, nil, nil

	case "webhook":
		if ac.URL == "" {
			return nil, nil, fmt.Errorf("webhook action requires a non-empty url")
		}
		if _, err := url.ParseRequestURI(ac.URL); err != nil {
			return nil, nil, fmt.Errorf("webhook action url %q: %w", ac.URL, err)
		}
		timeout := 5 * time.Second
		if ac.Timeout != "" {
			d, err := time.ParseDuration(ac.Timeout)
			if err != nil {
				return nil, nil, fmt.Errorf("webhook action timeout %q: %w", ac.Timeout, err)
			}
			if d <= 0 {
				return nil, nil, fmt.Errorf("webhook action timeout must be > 0")
			}
			timeout = d
		}
		maxAttempts := 3
		if ac.MaxAttempts != 0 {
			if ac.MaxAttempts < 1 {
				return nil, nil, fmt.Errorf("webhook action max_attempts must be >= 1")
			}
			maxAttempts = ac.MaxAttempts
		}
		return newWebhookAction(ac.URL, ac.Secret, ruleName, maxAttempts, timeout, ac.Headers, logger), nil, nil

	case "flowspec":
		mgr, ttl, action, err := buildFlowspecManager(ac, logger)
		if err != nil {
			return nil, nil, err
		}
		return &FlowspecAction{manager: mgr, ttl: ttl, action: action}, mgr, nil

	case "global-correlate":
		if o == nil || o.globalVisibility == nil {
			return nil, nil, fmt.Errorf(
				"global-correlate action requires an external provider: " +
					"set external.ripestat.enabled: true")
		}
		cacheTTL := o.defaultCacheTTL
		if ac.CacheTTL != "" {
			d, err := time.ParseDuration(ac.CacheTTL)
			if err != nil {
				return nil, nil, fmt.Errorf("global-correlate action cache_ttl %q: %w", ac.CacheTTL, err)
			}
			if d < 0 {
				return nil, nil, fmt.Errorf("global-correlate action cache_ttl must not be negative")
			}
			cacheTTL = d
		}
		return newGlobalCorrelateAction(o.globalVisibility, cacheTTL, logger), nil, nil

	default:
		return nil, nil, fmt.Errorf("unknown action type %q", ac.Type)
	}
}

func buildFlowspecManager(ac config.ActionConfig, logger *slog.Logger) (*flowspec.Manager, time.Duration, flowspec.FlowspecRuleAction, error) {
	ttl := time.Hour
	if ac.TTL != "" {
		d, err := time.ParseDuration(ac.TTL)
		if err != nil {
			return nil, 0, "", fmt.Errorf("flowspec action ttl %q: %w", ac.TTL, err)
		}
		if d <= 0 {
			return nil, 0, "", fmt.Errorf("flowspec action ttl must be > 0")
		}
		ttl = d
	}

	reaperInterval := 30 * time.Second
	if ac.ReaperInterval != "" {
		d, err := time.ParseDuration(ac.ReaperInterval)
		if err != nil {
			return nil, 0, "", fmt.Errorf("flowspec action reaper_interval %q: %w", ac.ReaperInterval, err)
		}
		if d <= 0 {
			return nil, 0, "", fmt.Errorf("flowspec action reaper_interval must be > 0")
		}
		reaperInterval = d
	}

	approvalTimeout := 10 * time.Second
	if ac.ApprovalTimeout != "" {
		d, err := time.ParseDuration(ac.ApprovalTimeout)
		if err != nil {
			return nil, 0, "", fmt.Errorf("flowspec action approval_timeout %q: %w", ac.ApprovalTimeout, err)
		}
		if d <= 0 {
			return nil, 0, "", fmt.Errorf("flowspec action approval_timeout must be > 0")
		}
		approvalTimeout = d
	}

	action := flowspec.FlowspecActionDrop
	if ac.RuleAction != "" {
		switch flowspec.FlowspecRuleAction(ac.RuleAction) {
		case flowspec.FlowspecActionDrop, flowspec.FlowspecActionRateLimit:
			action = flowspec.FlowspecRuleAction(ac.RuleAction)
		default:
			return nil, 0, "", fmt.Errorf("flowspec action rule_action %q: must be \"drop\" or \"rate-limit\"", ac.RuleAction)
		}
	}

	maxRules := 100
	if ac.MaxRules != 0 {
		maxRules = ac.MaxRules
	}

	mgr, err := flowspec.NewManager(flowspec.ManagerConfig{
		GoBGPAddress:    ac.GoBGPAddress,
		MaxRules:        maxRules,
		DefaultTTL:      ttl,
		DefaultAction:   action,
		DryRun:          ac.DryRun,
		ReaperInterval:  reaperInterval,
		ApprovalWebhook: ac.ApprovalWebhook,
		ApprovalTimeout: approvalTimeout,
	}, logger)
	if err != nil {
		return nil, 0, "", fmt.Errorf("flowspec manager: %w", err)
	}

	return mgr, ttl, action, nil
}

func parsePostures(ss []string) ([]types.SecurityPosture, error) {
	postures := make([]types.SecurityPosture, 0, len(ss))
	for _, s := range ss {
		switch types.SecurityPosture(s) {
		case types.PostureSecured,
			types.PostureOriginOnly,
			types.PosturePathSuspect,
			types.PosturePathOnly,
			types.PostureUnverified,
			types.PostureOriginInvalid:
			postures = append(postures, types.SecurityPosture(s))
		default:
			return nil, fmt.Errorf("unknown posture %q", s)
		}
	}
	return postures, nil
}
