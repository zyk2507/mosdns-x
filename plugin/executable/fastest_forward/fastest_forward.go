/*
 * Copyright (C) 2020-2025, zyk2507
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package fastestforward

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ping/ping"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/bundled_upstream"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/upstream"
	"github.com/pmkol/mosdns-x/pkg/utils"
	fastforward "github.com/pmkol/mosdns-x/plugin/executable/fast_forward"
)

const (
	PluginType = "fastest_forward"

	defaultProbeTimeout     = 200 * time.Millisecond
	defaultProbePortTCP     = 80
	defaultProbePortUDP     = 53
	defaultProbeNetwork     = "tcp"
	defaultProbeConcurrency = 4

	probeMethodTCP  = "tcp"
	probeMethodUDP  = "udp"
	probeMethodICMP = "icmp"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*fastestForward)(nil)

type Args struct {
	Upstream            []*fastforward.UpstreamConfig `yaml:"upstream" mapstructure:"upstream"`
	CA                  []string                      `yaml:"ca" mapstructure:"ca"`
	ProbeTimeout        int                           `yaml:"probe_timeout" mapstructure:"probe_timeout"`                 // in milliseconds
	ProbePort           int                           `yaml:"probe_port" mapstructure:"probe_port"`                       // tcp/udp port for latency probing
	ProbeNetwork        string                        `yaml:"probe_network" mapstructure:"probe_network"`                 // defaults to tcp
	ProbeMaxConcurrency int                           `yaml:"probe_max_concurrency" mapstructure:"probe_max_concurrency"` // defaults to 4
	ProbeMethod         string                        `yaml:"probe_method" mapstructure:"probe_method"`                   // defaults to tcp
	CollectTimeout      int                           `yaml:"collect_timeout" mapstructure:"collect_timeout"`             // wait to collect responses (ms); 0 disables
}

type fastestForward struct {
	*coremain.BP
	args *Args

	upstreamWrappers []bundled_upstream.Upstream
	upstreamsCloser  []io.Closer

	probeTimeout    time.Duration
	probeNetwork    string
	probePort       string
	probeEnabled    bool
	probeConcurrent int
	probeMethod     string
	collectTimeout  time.Duration
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newFastestForward(bp, args.(*Args))
}

func newFastestForward(bp *coremain.BP, args *Args) (*fastestForward, error) {
	if len(args.Upstream) == 0 {
		return nil, errors.New("no upstream is configured")
	}

	f := &fastestForward{
		BP:               bp,
		args:             args,
		probeTimeout:     getProbeTimeout(args.ProbeTimeout),
		probeConcurrent:  getProbeConcurrency(args.ProbeMaxConcurrency),
		probeEnabled:     true,
		collectTimeout:   getCollectTimeout(args.CollectTimeout),
		upstreamWrappers: make([]bundled_upstream.Upstream, 0, len(args.Upstream)),
		upstreamsCloser:  make([]io.Closer, 0, len(args.Upstream)),
	}

	f.probeMethod, f.probeNetwork = resolveProbeMethod(args.ProbeMethod, args.ProbeNetwork)

	if err := f.setProbePort(args.ProbePort); err != nil {
		return nil, err
	}

	// rootCAs
	var rootCAs *x509.CertPool
	if len(args.CA) != 0 {
		var err error
		rootCAs, err = utils.LoadCertPool(args.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca: %w", err)
		}
	}

	for i, c := range args.Upstream {
		if len(c.Addr) == 0 {
			return nil, errors.New("missing server addr")
		}

		if strings.HasPrefix(c.Addr, "udpme://") {
			u := newUDPME(c.Addr[8:], c.Trusted)
			f.upstreamWrappers = append(f.upstreamWrappers, u)
			if i == 0 {
				u.trusted = true
			}
			continue
		}

		opt := &upstream.Opt{
			DialAddr:       c.DialAddr,
			Socks5:         c.Socks5,
			S5Username:     c.S5Username,
			S5Password:     c.S5Password,
			SoMark:         c.SoMark,
			BindToDevice:   c.BindToDevice,
			IdleTimeout:    time.Duration(c.IdleTimeout) * time.Second,
			MaxConns:       c.MaxConns,
			EnablePipeline: c.EnablePipeline,
			Bootstrap:      c.Bootstrap,
			Insecure:       c.Insecure,
			RootCAs:        rootCAs,
			KernelTX:       c.KernelTX,
			KernelRX:       c.KernelRX,
			Logger:         bp.L(),
		}

		u, err := upstream.NewUpstream(c.Addr, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream: %w", err)
		}

		w := &upstreamWrapper{
			address: c.Addr,
			trusted: c.Trusted,
			u:       u,
		}

		if i == 0 { // Set first upstream as trusted upstream.
			w.trusted = true
		}

		f.upstreamWrappers = append(f.upstreamWrappers, w)
		f.upstreamsCloser = append(f.upstreamsCloser, u)
	}

	return f, nil
}

func getProbeTimeout(v int) time.Duration {
	if v <= 0 {
		return defaultProbeTimeout
	}
	return time.Duration(v) * time.Millisecond
}

func resolveProbeMethod(method, network string) (string, string) {
	if m := normalizeProbeMethod(method); m != "" {
		switch m {
		case probeMethodICMP:
			return probeMethodICMP, ""
		case probeMethodUDP:
			return probeMethodUDP, probeMethodUDP
		default:
			return probeMethodTCP, probeMethodTCP
		}
	}

	switch normalizeProbeMethod(network) {
	case probeMethodUDP:
		return probeMethodUDP, probeMethodUDP
	case probeMethodICMP:
		return probeMethodICMP, ""
	default:
		return probeMethodTCP, probeMethodTCP
	}
}

func normalizeProbeMethod(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case probeMethodTCP, probeMethodUDP, probeMethodICMP:
		return v
	default:
		return ""
	}
}

func getProbeConcurrency(v int) int {
	if v <= 0 {
		return defaultProbeConcurrency
	}
	return v
}

func getCollectTimeout(v int) time.Duration {
	if v <= 0 {
		return 0
	}
	return time.Duration(v) * time.Millisecond
}

func (f *fastestForward) setProbePort(port int) error {
	if f.probeMethod == probeMethodICMP {
		f.probePort = ""
		f.probeEnabled = true
		return nil
	}

	if port == 0 {
		switch f.probeMethod {
		case probeMethodUDP:
			port = defaultProbePortUDP
		default:
			port = defaultProbePortTCP
		}
	}

	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid probe_port %d", port)
	}

	f.probePort = strconv.Itoa(port)
	f.probeEnabled = true
	return nil
}

type upstreamWrapper struct {
	address string
	trusted bool
	u       upstream.Upstream
}

func (u *upstreamWrapper) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	q.Compress = true
	return u.u.ExchangeContext(ctx, q)
}

func (u *upstreamWrapper) Address() string {
	return u.address
}

func (u *upstreamWrapper) Trusted() bool {
	return u.trusted
}

func (f *fastestForward) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if err := f.exec(ctx, qCtx); err != nil {
		return err
	}
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (f *fastestForward) exec(ctx context.Context, qCtx *query_context.Context) error {
	var (
		r   *dns.Msg
		err error
	)
	r, err = f.exchangeBest(ctx, qCtx)
	if err != nil {
		return err
	}
	qCtx.SetResponse(r)
	if r != nil {
		f.probeResponseLatency(ctx, qCtx, r)
	}
	return nil
}

type collectedResult struct {
	resp        *dns.Msg
	err         error
	source      bundled_upstream.Upstream
	ipLatency   time.Duration
	ipLatencyOK bool
	bestIP      string
	latencyDone chan struct{}
}

func (r *collectedResult) waitLatency(ctx context.Context) bool {
	if r.latencyDone == nil {
		return false
	}

	select {
	case <-r.latencyDone:
		return true
	case <-ctx.Done():
		return false
	}
}

func (f *fastestForward) exchangeBest(ctx context.Context, qCtx *query_context.Context) (*dns.Msg, error) {
	total := len(f.upstreamWrappers)
	if total == 0 {
		return nil, bundled_upstream.ErrAllFailed
	}

	query := qCtx.Q()
	resultsCh := make(chan *collectedResult, total)
	for _, u := range f.upstreamWrappers {
		u := u
		msgCopy := query.Copy()
		go func() {
			resp, err := u.Exchange(ctx, msgCopy)
			res := &collectedResult{
				resp:   resp,
				err:    err,
				source: u,
			}
			if err == nil && resp != nil && f.probeEnabled {
				done := make(chan struct{})
				res.latencyDone = done
				go func(respMsg *dns.Msg) {
					latency, bestIP, measured := f.measureResponseLatency(ctx, qCtx, respMsg)
					res.ipLatency = latency
					res.ipLatencyOK = measured
					res.bestIP = bestIP
					close(done)
				}(resp)
			}
			resultsCh <- res
		}()
	}

	results := make([]*collectedResult, 0, total)
	var timer *time.Timer
	if f.collectTimeout > 0 {
		timer = time.NewTimer(f.collectTimeout)
		defer timer.Stop()
	}

	collected := 0

collectLoop:
	for collected < total {
		if timer == nil {
			select {
			case res := <-resultsCh:
				collected++
				results = append(results, res)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}

		select {
		case res := <-resultsCh:
			collected++
			results = append(results, res)
		case <-timer.C:
			timer = nil
			break collectLoop
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

drainLoop:
	for collected < total {
		select {
		case res := <-resultsCh:
			collected++
			results = append(results, res)
		default:
			break drainLoop
		}
	}

	return f.selectBestResponse(ctx, qCtx, results)
}

func (f *fastestForward) selectBestResponse(ctx context.Context, qCtx *query_context.Context, results []*collectedResult) (*dns.Msg, error) {
	if len(results) == 0 {
		return nil, bundled_upstream.ErrAllFailed
	}

	var (
		bestResp       *dns.Msg
		bestLatency    time.Duration
		bestMeasured   bool
		bestSource     bundled_upstream.Upstream
		bestIP         string
		fallbackResp   *dns.Msg
		fallbackSource bundled_upstream.Upstream
	)

	for _, res := range results {
		if res == nil {
			continue
		}
		if res.err != nil {
			f.L().Warn("upstream err", qCtx.InfoField(), zap.String("addr", res.source.Address()))
			continue
		}
		if res.resp == nil {
			continue
		}
		if !f.probeEnabled {
			if fallbackResp == nil {
				fallbackResp = res.resp
				fallbackSource = res.source
			}
			continue
		}

		ready := res.waitLatency(ctx)
		if res.latencyDone != nil {
			if ready {
				if res.ipLatencyOK {
					f.L().Debug("probe measurement complete", qCtx.InfoField(),
						zap.String("addr", res.source.Address()),
						zap.String("ip", res.bestIP),
						zap.Duration("ip_latency", res.ipLatency),
					)
				} else {
					f.L().Debug("probe measurement unavailable", qCtx.InfoField(),
						zap.String("addr", res.source.Address()),
						zap.String("reason", "no latency measured"),
					)
				}
			} else {
				f.L().Debug("probe wait timeout", qCtx.InfoField(),
					zap.String("addr", res.source.Address()),
				)
			}
		}

		if res.ipLatencyOK {
			if !bestMeasured || res.ipLatency < bestLatency {
				bestResp = res.resp
				bestLatency = res.ipLatency
				bestMeasured = true
				bestSource = res.source
				bestIP = res.bestIP
			}
			continue
		}

		if !bestMeasured && fallbackResp == nil {
			fallbackResp = res.resp
			fallbackSource = res.source
		}
	}

	if bestMeasured && bestResp != nil {
		logFields := []zap.Field{
			qCtx.InfoField(),
			zap.String("addr", bestSource.Address()),
			zap.Duration("ip_latency", bestLatency),
			zap.String("ip", bestIP),
		}
		f.L().Debug("selected lowest latency response", logFields...)
		return bestResp, nil
	}

	if fallbackResp != nil {
		if fallbackSource != nil {
			logFields := []zap.Field{
				qCtx.InfoField(),
				zap.String("addr", fallbackSource.Address()),
			}
			f.L().Debug("selected response without IP latency measurement", logFields...)
		}
		return fallbackResp, nil
	}

	return nil, bundled_upstream.ErrAllFailed
}

func (f *fastestForward) measureResponseLatency(ctx context.Context, qCtx *query_context.Context, resp *dns.Msg) (time.Duration, string, bool) {
	if !f.probeEnabled || resp == nil {
		return 0, "", false
	}

	ips := collectResponseIPs(resp)
	if len(ips) == 0 {
		return 0, "", false
	}

	probeCtx := ctx
	var cancel context.CancelFunc
	if f.probeTimeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, f.probeTimeout)
		defer cancel()
	}

	g, gctx := errgroup.WithContext(probeCtx)
	if f.probeConcurrent > 0 {
		g.SetLimit(f.probeConcurrent)
	}

	type ipLatencyResult struct {
		ip      string
		latency time.Duration
	}

	latencyCh := make(chan ipLatencyResult, len(ips))
	for _, ip := range ips {
		ip := ip
		g.Go(func() error {
			if latency, ok := f.calcIPLatency(gctx, qCtx, ip, false); ok {
				select {
				case latencyCh <- ipLatencyResult{ip: ip, latency: latency}:
				default:
				}
			}
			return nil
		})
	}

	err := g.Wait()
	close(latencyCh)

	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		f.L().Debug("latency probe routine error", qCtx.InfoField(), zap.Error(err))
	}

	var (
		bestLatency time.Duration
		bestIP      string
		hasLatency  bool
	)
	for res := range latencyCh {
		if !hasLatency || res.latency < bestLatency {
			bestLatency = res.latency
			bestIP = res.ip
			hasLatency = true
		}
	}

	return bestLatency, bestIP, hasLatency
}

func (f *fastestForward) probeResponseLatency(ctx context.Context, qCtx *query_context.Context, resp *dns.Msg) {
	if !f.probeEnabled || resp == nil {
		return
	}

	ips := collectResponseIPs(resp)
	if len(ips) == 0 {
		return
	}

	probeCtx := ctx
	var cancel context.CancelFunc
	if f.probeTimeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, f.probeTimeout)
		defer cancel()
	}

	g, gctx := errgroup.WithContext(probeCtx)
	if f.probeConcurrent > 0 {
		g.SetLimit(f.probeConcurrent)
	}

	for _, ip := range ips {
		ip := ip
		g.Go(func() error {
			_, _ = f.calcIPLatency(gctx, qCtx, ip, true)
			return nil
		})
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		f.L().Debug("latency probe routine error", qCtx.InfoField(), zap.Error(err))
	}
}

func (f *fastestForward) calcIPLatency(ctx context.Context, qCtx *query_context.Context, ip string, withLog bool) (time.Duration, bool) {
	if f.probeMethod == probeMethodICMP {
		return f.calcICMPLatency(ctx, qCtx, ip, withLog)
	}

	if latency, ok := f.calcDialLatency(ctx, qCtx, ip, withLog); ok {
		return latency, true
	}

	if f.probeMethod != probeMethodICMP {
		select {
		case <-ctx.Done():
			return 0, false
		default:
		}
		if withLog {
			f.L().Debug("latency probe falling back to icmp", qCtx.InfoField(), zap.String("ip", ip))
		}
		return f.calcICMPLatency(ctx, qCtx, ip, withLog)
	}

	return 0, false
}

func (f *fastestForward) calcDialLatency(ctx context.Context, qCtx *query_context.Context, ip string, withLog bool) (time.Duration, bool) {
	addr := net.JoinHostPort(ip, f.probePort)
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, f.probeNetwork, addr)
	if err != nil {
		if withLog {
			f.logDialFailure(ctx, qCtx, ip, err)
		}
		return 0, false
	}
	latency := time.Since(start)
	conn.Close()
	if withLog {
		f.L().Info("latency probe success", qCtx.InfoField(), zap.String("method", f.probeMethod), zap.String("ip", ip), zap.Duration("latency", latency))
	}
	return latency, true
}

func (f *fastestForward) logDialFailure(ctx context.Context, qCtx *query_context.Context, ip string, err error) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		f.L().Debug("latency probe timeout", qCtx.InfoField(), zap.String("method", f.probeMethod), zap.String("ip", ip))
		return
	}
	select {
	case <-ctx.Done():
		f.L().Debug("latency probe canceled", qCtx.InfoField(), zap.String("method", f.probeMethod), zap.String("ip", ip), zap.Error(err))
	default:
		f.L().Debug("latency probe failed", qCtx.InfoField(), zap.String("method", f.probeMethod), zap.String("ip", ip), zap.Error(err))
	}
}

func (f *fastestForward) calcICMPLatency(ctx context.Context, qCtx *query_context.Context, ip string, withLog bool) (time.Duration, bool) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		if withLog {
			f.L().Debug("latency probe init failed", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip), zap.Error(err))
		}
		return 0, false
	}
	pinger.Count = 1
	pinger.SetPrivileged(false)
	if f.probeTimeout > 0 {
		pinger.Timeout = f.probeTimeout
	}

	statsCh := make(chan *ping.Statistics, 1)
	pinger.OnFinish = func(stats *ping.Statistics) {
		statsCh <- stats
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- pinger.Run()
	}()

	select {
	case <-ctx.Done():
		pinger.Stop()
		runErr := <-errCh
		if withLog {
			if runErr != nil && !errors.Is(runErr, context.Canceled) {
				f.L().Debug("latency probe canceled", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip), zap.Error(runErr))
			} else {
				f.L().Debug("latency probe canceled", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip))
			}
		}
		return 0, false
	case err := <-errCh:
		if err != nil {
			if withLog {
				if errors.Is(err, context.DeadlineExceeded) {
					f.L().Debug("latency probe timeout", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip))
				} else {
					f.L().Debug("latency probe failed", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip), zap.Error(err))
				}
			}
			return 0, false
		}
	}

	var stats *ping.Statistics
	select {
	case stats = <-statsCh:
	default:
		stats = pinger.Statistics()
	}
	if stats == nil || stats.PacketsRecv == 0 {
		if withLog {
			f.L().Debug("latency probe failed", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip), zap.String("reason", "no reply"))
		}
		return 0, false
	}

	latency := stats.AvgRtt
	if latency <= 0 && len(stats.Rtts) > 0 {
		latency = stats.Rtts[0]
	}
	if latency <= 0 {
		if withLog {
			f.L().Debug("latency probe failed", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip), zap.String("reason", "invalid rtt"))
		}
		return 0, false
	}

	if withLog {
		f.L().Info("latency probe success", qCtx.InfoField(), zap.String("method", probeMethodICMP), zap.String("ip", ip), zap.Duration("latency", latency))
	}
	return latency, true
}

func collectResponseIPs(resp *dns.Msg) []string {
	if resp == nil || len(resp.Answer) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	var ips []string

	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ip := v.A.String()
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
		case *dns.AAAA:
			ip := v.AAAA.String()
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func (f *fastestForward) Shutdown() error {
	for _, u := range f.upstreamsCloser {
		u.Close()
	}
	return nil
}
