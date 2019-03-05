// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "proxy")
)

// field names used while logging
const (
	fieldMarker          = "marker"
	fieldSocket          = "socket"
	fieldFd              = "fd"
	fieldProxyRedirectID = "id"

	// portReuseDelay is the delay until a port is being reused
	portReuseDelay = 5 * time.Minute

	// redirectCreationAttempts is the number of attempts to create a redirect
	redirectCreationAttempts = 5
)

type DatapathUpdater interface {
	InstallProxyRules(proxyPort uint16, ingress bool, name string) error
	RemoveProxyRules(proxyPort uint16, ingress bool, name string) error
}

type ProxyPort struct {
	// Listener name (immutable)
	Name string
	// L7 parser type this port applies to (immutable)
	L7ParserType policy.L7ParserType
	// 'true' for ingress, 'false' for egress (immutable)
	Ingress bool
	// ProxyPort is the desired proxy listening port number.
	ProxyPort uint16
	// nRedirects is the number of redirects using this proxy port
	nRedirects int
	// Configured is true when the proxy is (being) configured, but not necessarily
	// acknowledged yet. This is reset to false when the underlying proxy listener
	// is removed.
	Configured bool
	// rulesPort congains the proxy port value configured to the datapath rules and
	// is non-zero when a proxy has been succesfully created and the
	// datapath rules have been created.
	rulesPort uint16
}

// Proxy maintains state about redirects
type Proxy struct {
	*envoy.XDSServer

	// stateDir is the path of the directory where the state of L7 proxies is
	// stored.
	stateDir string

	// mutex is the lock required when modifying any proxy datastructure
	mutex lock.RWMutex

	// rangeMin is the minimum port used for proxy port allocation
	rangeMin uint16

	// rangeMax is the maximum port used for proxy port allocation.
	// If port is unspecified, the proxy will automatically allocate
	// ports out of the rangeMin-rangeMax range.
	rangeMax uint16

	// redirects is the map of all redirect configurations indexed by
	// the redirect identifier. Redirects may be implemented by different
	// proxies.
	redirects map[string]*Redirect

	// Datapath updater for installing and removing proxy rules for a single
	// proxy port
	datapathUpdater DatapathUpdater
}

// StartProxySupport starts the servers to support L7 proxies: xDS GRPC server
// and access log server.
func StartProxySupport(minPort uint16, maxPort uint16, stateDir string,
	accessLogFile string, accessLogNotifier logger.LogRecordNotifier, accessLogMetadata []string,
	datapathUpdater DatapathUpdater) *Proxy {
	xdsServer := envoy.StartXDSServer(stateDir)

	if accessLogFile != "" {
		if err := logger.OpenLogfile(accessLogFile); err != nil {
			log.WithError(err).WithField(logger.FieldFilePath, accessLogFile).
				Warn("Cannot open L7 access log")
		}
	}

	if accessLogNotifier != nil {
		logger.SetNotifier(accessLogNotifier)
	}

	if len(accessLogMetadata) > 0 {
		logger.SetMetadata(accessLogMetadata)
	}

	envoy.StartAccessLogServer(stateDir, xdsServer, DefaultEndpointInfoRegistry)

	return &Proxy{
		XDSServer:       xdsServer,
		stateDir:        stateDir,
		rangeMin:        minPort,
		rangeMax:        maxPort,
		redirects:       make(map[string]*Redirect),
		datapathUpdater: datapathUpdater,
	}
}

var (
	// proxyPortsMutex protects access to allocatedPorts, portRandomized, and proxyPorts
	proxyPortsMutex lock.Mutex

	// allocatedPorts is the map of all allocated proxy ports
	allocatedPorts = make(map[uint16]struct{})

	portRandomizer = rand.New(rand.NewSource(time.Now().UnixNano()))

	// proxyPorts is a slice of all supported proxy ports
	proxyPorts = []ProxyPort{
		{
			L7ParserType: policy.ParserTypeHTTP,
			Ingress:      false,
			Name:         "cilium-http-egress",
		},
		{
			L7ParserType: policy.ParserTypeHTTP,
			Ingress:      true,
			Name:         "cilium-http-ingress",
		},
		{
			L7ParserType: policy.ParserTypeKafka,
			Ingress:      false,
			Name:         "cilium-kafka-egress",
		},
		{
			L7ParserType: policy.ParserTypeKafka,
			Ingress:      true,
			Name:         "cilium-kafka-ingress",
		},
		{
			L7ParserType: policy.ParserTypeDNS,
			Ingress:      false,
			Name:         "cilium-dns-egress",
		},
		{
			L7ParserType: policy.ParserTypeDNS,
			Ingress:      true,
			Name:         "cilium-dns-ingress",
		},
		{
			L7ParserType: policy.ParserTypeNone,
			Ingress:      false,
			Name:         "cilium-proxylib-egress",
		},
		{
			L7ParserType: policy.ParserTypeNone,
			Ingress:      true,
			Name:         "cilium-proxylib-ingress",
		},
	}
)

// Called with proxyPortsMutex held!
func (p *Proxy) isPortAvailable(openLocalPorts map[uint16]struct{}, port uint16) bool {
	if _, used := allocatedPorts[port]; used {
		return false // port already used
	}
	// Check that the low 6 bits are unique.
	// This is needed for the DSCP and mark matches on iptables
	// rules.
	// We only use a small number of proxy ports, so looping
	// over the map is fast
	if port&DSCPMask == 0 {
		return false // must have non-zero DSCP bits
	}
	for p := range allocatedPorts {
		if port&DSCPMask == p&DSCPMask {
			return false // low 6 bits not unique
		}
	}
	// Check that the port is not already open
	if _, alreadyOpen := openLocalPorts[port]; alreadyOpen {
		return false // port already open
	}

	return true
}

// Called with proxyPortsMutex held!
func (p *Proxy) allocatePort(port uint16) (uint16, error) {
	// Get a snapshot of the TCP and UDP ports already open locally.
	openLocalPorts, err := readOpenLocalPorts(append(procNetTCPFiles, procNetUDPFiles...))
	if err != nil {
		return 0, fmt.Errorf("couldn't read local ports from /proc: %s", err)
	}

	if p.isPortAvailable(openLocalPorts, port) {
		return port, nil
	}

	for _, r := range portRandomizer.Perm(int(p.rangeMax - p.rangeMin + 1)) {
		resPort := uint16(r) + p.rangeMin

		if p.isPortAvailable(openLocalPorts, resPort) {
			return resPort, nil
		}
	}

	return 0, fmt.Errorf("no available proxy ports")
}

func init() {
	// Sanity-check the proxy port values
	pmap := make(map[uint16]uint16, 64)
	for _, v := range proxyPorts {
		if v.ProxyPort != 0 {
			dscp := v.ProxyPort & DSCPMask
			if dscp == 0 {
				panic(fmt.Sprintf("Zero low 6 bits for %s ProxyPort %d", v.Name, v.ProxyPort))
			}
			if port, ok := pmap[dscp]; ok {
				panic(fmt.Sprintf("Overlapping low 6 bits for %s ProxyPort %d (already have %d)", v.Name, v.ProxyPort, port))
			}
			pmap[dscp] = v.ProxyPort
		}
	}
}

// Called with proxyPortsMutex held!
func (pp *ProxyPort) reservePort(port uint16) {
	allocatedPorts[port] = struct{}{}
	pp.Configured = true
	pp.ProxyPort = port
}

// Called with proxyPortsMutex held!
func findProxyPort(name string) *ProxyPort {
	for i := range proxyPorts {
		if proxyPorts[i].Name == name {
			return &proxyPorts[i]
		}
	}
	return nil
}

// ackProxyPort() marks the proxy as successfully created and creates or updates the datapath rules
// accordingly. Each call must eventually be paired with a corresponding RemoveProxyPort() call
// to keep the use count up-to-date.
// Must be called with proxyPortsMutex held!
func (p *Proxy) ackProxyPort(pp *ProxyPort) error {
	if pp.nRedirects == 0 {
		scopedLog := log.WithField("proxy port name", pp.Name)
		scopedLog.Debugf("Considering updating proxy port rules for %s:%d (old: %d)", pp.Name, pp.ProxyPort, pp.rulesPort)

		// Datapath rules are added only after we know the proxy configuration
		// with the actual port number has succeeded. Deletion of the rules
		// is delayed after the redirects have been removed to the point
		// when we know the port number changes. This is to reduce the churn
		// in the datapath, but means that the datapath rules may exist even
		// if the proxy is not currently configured.

		// Remove old rules, if any and for different port
		if pp.rulesPort != 0 && pp.rulesPort != pp.ProxyPort {
			scopedLog.Debugf("Removing old proxy port rules for %s:%d", pp.Name, pp.rulesPort)
			p.datapathUpdater.RemoveProxyRules(pp.rulesPort, pp.Ingress, pp.Name)
			pp.rulesPort = 0
		}
		// Add new rules, if needed
		if pp.rulesPort != pp.ProxyPort {
			// This should always succeed if we have managed to start-up properly
			scopedLog.Debugf("Adding new proxy port rules for %s:%d", pp.Name, pp.ProxyPort)
			err := p.datapathUpdater.InstallProxyRules(pp.ProxyPort, pp.Ingress, pp.Name)
			if err != nil {
				return fmt.Errorf("Can't install proxy rules for %s: %s", pp.Name, err)
			}
		}
		pp.rulesPort = pp.ProxyPort
	}
	pp.nRedirects++
	return nil
}

// AckProxyPort() marks the proxy as successfully created and creates or updates the datapath rules
// accordingly. Each call must eventually be paired with a corresponding RemoveProxyPort() call
// to keep the use count up-to-date.
func (p *Proxy) AckProxyPort(pp *ProxyPort) error {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	return p.ackProxyPort(pp)
}

// SetProxyPort() marks the proxy 'name' as successfully created with proxy port 'port' and creates
// or updates the datapath rules accordingly.
// May only be called once per proxy.
func (p *Proxy) SetProxyPort(name string, port uint16) error {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := findProxyPort(name)
	if pp == nil {
		return fmt.Errorf("Can't find proxy port %s", name)
	}
	if pp.nRedirects > 0 {
		return fmt.Errorf("Can't set proxy port to %d: proxy %s is already configured on %d", port, name, pp.ProxyPort)
	}
	pp.ProxyPort = port
	pp.Configured = true
	return p.ackProxyPort(pp)
}

// ReinstallRules is called by daemon reconfiguration to re-install proxy ports rules that
// were removed during the removal of all Cilium rules.
func (p *Proxy) ReinstallRules() {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	for _, pp := range proxyPorts {
		if pp.rulesPort > 0 {
			// This should always succeed if we have managed to start-up properly
			err := p.datapathUpdater.InstallProxyRules(pp.rulesPort, pp.Ingress, pp.Name)
			if err != nil {
				proxyPortsMutex.Unlock()
				panic(fmt.Sprintf("Can't install proxy rules for %s: %s", pp.Name, err))
			}
		}
	}
}

// ReleaseProxyPort() decreases the use count and frees the port if no users remain
func (p *Proxy) ReleaseProxyPort(name string) error {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := findProxyPort(name)
	if pp == nil {
		return fmt.Errorf("Can't find proxy port %s", name)
	}
	if pp.nRedirects == 0 {
		return fmt.Errorf("Can't release proxy port: proxy %s on %d has refcount 0", name, pp.ProxyPort)
	}

	pp.nRedirects--
	if pp.nRedirects == 0 {
		delete(allocatedPorts, pp.ProxyPort)
		// Force new port allocation the next time this ProxyPort is used.
		pp.Configured = false
		// Leave the datapath rules behind on the hope that they get reused later.
		// This becomes possible when we are able to keep the proxy listeners
		// configured also when there are no redirects.
		log.WithField(fieldProxyRedirectID, name).Debugf("Delayed release of proxy port %d", pp.ProxyPort)
	}

	return nil
}

func getProxyPort(l7Type policy.L7ParserType, ingress bool) *ProxyPort {
	portType := l7Type
	switch l7Type {
	case policy.ParserTypeDNS, policy.ParserTypeKafka, policy.ParserTypeHTTP:
	default:
		// "Unknown" parsers are assumed to be Proxylib (TCP) parsers, which
		// is registered with an empty string.
		portType = ""
	}
	// proxyPorts is small enough to not bother indexing it.
	for i := range proxyPorts {
		if proxyPorts[i].L7ParserType == portType && proxyPorts[i].Ingress == ingress {
			return &proxyPorts[i]
		}
	}
	return nil
}

func proxyNotFoundError(l7Type policy.L7ParserType, ingress bool) error {
	dir := "egress"
	if ingress {
		dir = "ingress"
	}
	return fmt.Errorf("unrecognized %s proxy type: %s", dir, l7Type)
}

// GetProxyPort() returns the fixed listen port for a proxy, if any.
func GetProxyPort(l7Type policy.L7ParserType, ingress bool) (uint16, string, error) {
	pp := getProxyPort(l7Type, ingress)
	if pp != nil {
		return pp.ProxyPort, pp.Name, nil
	}
	return 0, "", proxyNotFoundError(l7Type, ingress)
}

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is already in place, only the rules will be
// updated.
func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, localEndpoint logger.EndpointUpdater,
	wg *completion.WaitGroup) (redir *Redirect, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {

	p.mutex.Lock()
	defer func() {
		p.UpdateRedirectMetrics()
		p.mutex.Unlock()
	}()

	scopedLog := log.WithField(fieldProxyRedirectID, id)

	var revertStack revert.RevertStack
	revertFunc = revertStack.Revert

	var ok bool
	if redir, ok = p.redirects[id]; ok {
		redir.mutex.Lock()

		if redir.parserType == l4.L7Parser {
			updateRevertFunc := redir.updateRules(l4)
			revertStack.Push(updateRevertFunc)
			var implUpdateRevertFunc revert.RevertFunc
			implUpdateRevertFunc, err = redir.implementation.UpdateRules(wg, l4)
			if err != nil {
				err = fmt.Errorf("unable to update existing redirect: %s", err)
				return
			}
			revertStack.Push(implUpdateRevertFunc)

			redir.lastUpdated = time.Now()

			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("updated existing ", l4.L7Parser, " proxy instance")

			redir.mutex.Unlock()
			return
		}

		var removeRevertFunc revert.RevertFunc
		err, finalizeFunc, removeRevertFunc = p.removeRedirect(id, wg)
		redir.mutex.Unlock()

		if err != nil {
			err = fmt.Errorf("unable to remove old redirect: %s", err)
			return
		}

		revertStack.Push(removeRevertFunc)
	}

	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := getProxyPort(l4.L7Parser, l4.Ingress)
	if pp == nil {
		err = proxyNotFoundError(l4.L7Parser, l4.Ingress)
		return
	}
	to := pp.ProxyPort
	listenerName := pp.Name

	redir = newRedirect(localEndpoint, listenerName)
	redir.dstPort = uint16(l4.Port)
	redir.endpointID = localEndpoint.GetID()
	redir.ingress = l4.Ingress
	redir.parserType = l4.L7Parser
	redir.updateRules(l4)
	// Rely on create*Redirect to update rules, unlike the update case above.

	for nRetry := 0; ; nRetry++ {
		if !pp.Configured {
			// Try allocate (the configured) port, but only if the proxy has not been already configured.
			// Fall back to dynamic allocation the configured port can not be allocated.
			// When retrying, this will try again with fixed port number if that port is still available.
			to, err = p.allocatePort(to)
			if err != nil {
				revertFunc() // Ignore errors while reverting. This is best-effort.
				return
			}
		}
		redir.ProxyPort = to

		switch l4.L7Parser {
		case policy.ParserTypeDNS:
			redir.implementation, err = createDNSRedirect(redir, dnsConfiguration{}, DefaultEndpointInfoRegistry)

		case policy.ParserTypeKafka:
			redir.implementation, err = createKafkaRedirect(redir, kafkaConfiguration{}, DefaultEndpointInfoRegistry)

		case policy.ParserTypeHTTP:
			redir.implementation, err = createEnvoyRedirect(redir, p.stateDir, p.XDSServer, wg)
		default:
			redir.implementation, err = createEnvoyRedirect(redir, p.stateDir, p.XDSServer, wg)
		}

		switch {
		case err == nil:
			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("Created new ", l4.L7Parser, " proxy instance")
			p.redirects[id] = redir
			// must mark the proxyPort configured while we still hold the lock to prevent racing between
			// two parallel runs
			pp.reservePort(to)

			revertStack.Push(func() error {
				completionCtx, cancel := context.WithCancel(context.Background())
				proxyWaitGroup := completion.NewWaitGroup(completionCtx)
				err, finalize, _ := p.RemoveRedirect(id, proxyWaitGroup)
				// Don't wait for an ACK. This is best-effort. Just clean up the completions.
				cancel()
				proxyWaitGroup.Wait() // Ignore the returned error.
				if err == nil && finalize != nil {
					finalize()
				}
				return err
			})

			// Set the proxy port only after an ACK is received.
			removeFinalizeFunc := finalizeFunc
			finalizeFunc = func() {
				if removeFinalizeFunc != nil {
					removeFinalizeFunc()
				}

				err := p.AckProxyPort(pp)
				if err != nil {
					// Finalize functions can't error out. This failure can only
					// happen if there is an internal Cilium logic error regarding
					// installation of iptables rules.
					panic(err)
				}
			}
			return

		// an error occurred, and we have no more retries
		case nRetry >= redirectCreationAttempts:
			scopedLog.WithError(err).Error("Unable to create ", l4.L7Parser, " proxy")

			revertFunc() // Ignore errors while reverting. This is best-effort.
			return

		// an error occurred and we can retry
		default:
			scopedLog.WithError(err).Warning("Unable to create ", l4.L7Parser, " proxy, will retry")
		}
	}
}

// RemoveRedirect removes an existing redirect.
func (p *Proxy) RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	p.mutex.Lock()
	defer func() {
		p.UpdateRedirectMetrics()
		p.mutex.Unlock()
	}()
	return p.removeRedirect(id, wg)
}

// removeRedirect removes an existing redirect. p.mutex must be held
// p.mutex must NOT be held when the returned finalize and revert functions are called!
func (p *Proxy) removeRedirect(id string, wg *completion.WaitGroup) (err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	log.WithField(fieldProxyRedirectID, id).
		Debug("Removing proxy redirect")

	r, ok := p.redirects[id]
	if !ok {
		return fmt.Errorf("unable to find redirect %s", id), nil, nil
	}
	delete(p.redirects, id)

	implFinalizeFunc, implRevertFunc := r.implementation.Close(wg)

	// Delay the release and reuse of the port number so it is guaranteed to be
	// safe to listen on the port again. This can't be reverted, so do it in a
	// FinalizeFunc.
	proxyPort := r.ProxyPort
	listenerName := r.listenerName

	finalizeFunc = func() {
		if implFinalizeFunc != nil {
			implFinalizeFunc()
		}

		go func() {
			time.Sleep(portReuseDelay)

			err := p.ReleaseProxyPort(listenerName)
			if err != nil {
				log.WithField(fieldProxyRedirectID, id).WithError(err).Warningf("Releasing proxy port %d failed", proxyPort)
			}
		}()
	}

	revertFunc = func() error {
		if implRevertFunc != nil {
			return implRevertFunc()
		}

		p.mutex.Lock()
		p.redirects[id] = r
		p.mutex.Unlock()

		return nil
	}

	return
}

// ChangeLogLevel changes proxy log level to correspond to the logrus log level 'level'.
func ChangeLogLevel(level logrus.Level) {
	if envoyProxy != nil {
		envoyProxy.ChangeLogLevel(level)
	}
}

// GetStatusModel returns the proxy status as API model
func (p *Proxy) GetStatusModel() *models.ProxyStatus {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return &models.ProxyStatus{
		IP:        node.GetInternalIPv4().String(),
		PortRange: fmt.Sprintf("%d-%d", p.rangeMin, p.rangeMax),
	}
}

// UpdateRedirectMetrics updates the redirect metrics per application protocol
// in Prometheus. Lock needs to be held to call this function.
func (p *Proxy) UpdateRedirectMetrics() {
	result := map[string]int{}
	for _, redirect := range p.redirects {
		result[string(redirect.parserType)]++
	}
	for proto, count := range result {
		metrics.ProxyRedirects.WithLabelValues(proto).Set(float64(count))
	}
}
