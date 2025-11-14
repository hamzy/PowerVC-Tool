// Copyright 2025 IBM Corp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/pagination"

	"github.com/IBM/go-sdk-core/v5/core"

	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"

	"github.com/IBM/platform-services-go-sdk/globalcatalogv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"

	"github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
)

// stringArray is a custom type to hold an array of strings.
type stringArray []string

// String implements the flag.Value interface's String method.
func (s *stringArray) String() string {
	return strings.Join(*s, ",")
}

// Set implements the flag.Value interface's Set method.
// It appends the provided value to the string array.
func (s *stringArray) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type bastionInformation struct {
	Valid        bool
	Metadata     string
	Username     string
	InstallerRsa string

	ClusterName  string
	InfraID      string
	IPAddress    string
	NumVMs       int
}

func watchInstallationCommand(watchInstallationFlags *flag.FlagSet, args []string) error {
	var (
		out                 io.Writer
		apiKey              string
		ptrCloud            *string
		ptrDomainName       *string
		bastionMetadatas    stringArray
		ptrBastionUsername  *string
		ptrInstallerRsa     *string
		ptrDhcpSubnet       *string
		ptrDhcpNetmask      *string
		ptrDhcpRouter       *string
		ptrDhcpDnsServers   *string
		ptrEnableDhcpd      *string
		ptrShouldDebug      *string
		enableDhcpd         = false
		ctx                 context.Context
		cancel              context.CancelFunc
		connCompute         *gophercloud.ServiceClient
		knownServers        = sets.Set[string]{}
		newServerSet        sets.Set[string]
		addedServersSet     sets.Set[string]
		deletedServerSet    sets.Set[string]
		allServers          []servers.Server
		bastionInformations []bastionInformation
		err                 error
	)

	apiKey = os.Getenv("IBMCLOUD_API_KEY")

	ptrCloud = watchInstallationFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrDomainName = watchInstallationFlags.String("domainName", "", "The DNS domain to use")
	watchInstallationFlags.Var(&bastionMetadatas, "bastionMetadata", "A list of bastion names (can be specified multiple times)")
	ptrBastionUsername = watchInstallationFlags.String("bastionUsername", "", "The username of the bastion VM to use")
	ptrInstallerRsa = watchInstallationFlags.String("bastionRsa", "", "The RSA filename for the bastion VM to use")
	ptrEnableDhcpd = watchInstallationFlags.String("enableDhcpd", "false", "Should enable the dhcpd server")
	ptrDhcpSubnet = watchInstallationFlags.String("dhcpSubnet", "", "The subnet for a DHCP request")
	ptrDhcpNetmask = watchInstallationFlags.String("dhcpNetmask", "", "The netmask for a DHCP request")
	ptrDhcpRouter = watchInstallationFlags.String("dhcpRouter", "", "The router for a DHCP request")
	ptrDhcpDnsServers = watchInstallationFlags.String("dhcpDnsServers",  "", "The DNS servers for a DHCP request")
	ptrShouldDebug = watchInstallationFlags.String("shouldDebug", "false", "Should output debug output")

	watchInstallationFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		return fmt.Errorf("Error: --cloud not specified")
	}
	if ptrDomainName == nil || *ptrDomainName == "" {
		return fmt.Errorf("Error: --domainName not specified")
	}
	if len(bastionMetadatas) == 0 {
		return fmt.Errorf("Error: --bastionMetadata not specified")
	}
	if ptrBastionUsername == nil || *ptrBastionUsername == "" {
		return fmt.Errorf("Error: --bastionUsername not specified")
	}
	if ptrInstallerRsa == nil || *ptrInstallerRsa == "" {
		return fmt.Errorf("Error: --bastionRsa not specified")
	}
	if ptrDhcpSubnet == nil || *ptrDhcpSubnet == "" {
		return fmt.Errorf("Error: --dhcpSubnet not specified")
	}
	if ptrDhcpNetmask == nil || *ptrDhcpNetmask == "" {
		return fmt.Errorf("Error: --dhcpNetmask not specified")
	}
	if ptrDhcpRouter == nil || *ptrDhcpRouter == "" {
		return fmt.Errorf("Error: --dhcpRouter not specified")
	}
	if ptrDhcpDnsServers == nil || *ptrDhcpDnsServers == "" {
		return fmt.Errorf("Error: --dhcpDnsServers not specified")
	}

	switch strings.ToLower(*ptrEnableDhcpd) {
	case "true":
		enableDhcpd = true
	case "false":
		enableDhcpd = false
	default:
		return fmt.Errorf("Error: enableDhcpd is not true/false (%s)\n", *ptrShouldDebug)
	}

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		return fmt.Errorf("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
	}

	if shouldDebug {
		out = os.Stderr
	} else {
		out = io.Discard
	}
	log = &logrus.Logger{
		Out:       out,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}

	fmt.Fprintf(os.Stderr, "Program version is %v, release = %v\n", version, release)

	ctx, cancel = context.WithTimeout(context.TODO(), 5*time.Minute)
	defer cancel()

	connCompute, err = NewServiceClient(ctx, "compute", DefaultClientOpts(*ptrCloud))
	if err != nil {
		return err
	}
//	log.Debugf("connCompute = %+v", connCompute)

	bastionInformations = make([]bastionInformation, 0)
	for _, bastionMetadata := range bastionMetadatas {
		bastionInformations = append(bastionInformations, bastionInformation{
			Valid:        false,
			Metadata:     bastionMetadata,
			Username:     *ptrBastionUsername,
			InstallerRsa: *ptrInstallerRsa,
		})
	}
	log.Debugf("bastionInformations = %+v", bastionInformations)

	for true {
		log.Debugf("Waking up")

		ctx, cancel = context.WithTimeout(context.TODO(), 1*time.Hour)
		defer cancel()

		allServers, err = getAllServers(ctx, connCompute)
		if err != nil {
			return err
		}

		newServerSet = getServerSet(allServers)
		addedServersSet = newServerSet.Difference(knownServers)
		deletedServerSet = knownServers.Difference(newServerSet)
		log.Debugf("knownServers     = %+v", knownServers)
		log.Debugf("newServerSet     = %+v", newServerSet)
		log.Debugf("addedServersSet  = %+v", addedServersSet)
		log.Debugf("deletedServerSet = %+v", deletedServerSet)

		// If we haven't added new servers or deleted old servers, then try again
		if addedServersSet.Len() == 0 && deletedServerSet.Len() == 0 {
			log.Debugf("Sleeping")

			time.Sleep(30 * time.Second)

			continue
		}

		knownServers = newServerSet

		// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

		err = updateBastionInformations(ctx, *ptrCloud, bastionInformations)
		if err != nil {
			return err
		}

		fmt.Println("8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------")

		if enableDhcpd {
			filename := "/tmp/dhcpd.conf"
			err = dhcpdConf(ctx,
				filename,
				*ptrCloud,
				*ptrDomainName,
				*ptrDhcpSubnet,
				*ptrDhcpNetmask,
				*ptrDhcpRouter,
				*ptrDhcpDnsServers,
			)
			if err != nil {
				return err
			}

			err = runSplitCommand([]string{
				"sudo",
				"/usr/bin/cp",
				filename,
				"/etc/dhcp/dhcpd.conf",
			})
			if err != nil {
				return err
			}

			err = runSplitCommand([]string{
				"sudo",
				"systemctl",
				"restart",
				"dhcpd.service",
			})
			if err != nil {
				return err
			}
		}

		fmt.Println("8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------")

		err = haproxyCfg(ctx, *ptrCloud, bastionInformations)
		if err != nil {
			return err
		}

		fmt.Println("8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------")

		err = dnsRecords(ctx,
			*ptrCloud,
			apiKey,
			*ptrDomainName,
			bastionInformations,
			knownServers,
			addedServersSet,
			deletedServerSet,
		)
		if err != nil {
			return err
		}

		log.Debugf("Sleeping")

		time.Sleep(30 * time.Second)
	}

	return nil
}

type MinimalMetadata struct {
	ClusterName string `json:"clusterName"`
	ClusterID   string `json:"clusterID"`
	InfraID     string `json:"infraID"`
}

func getMetadataClusterName(filename string) (clusterName string, infraID string, err error) {
	var (
		content  []byte
		metadata MinimalMetadata
	)

	content, err = ioutil.ReadFile(filename)
	if err != nil {
		log.Debugf("Error when opening file: %v", err)
		return
	}
	log.Debugf("getMetadataClusterName: content = %s", string(content))

	err = json.Unmarshal(content, &metadata)
	if err != nil {
		log.Debugf("Error during Unmarshal(): %v", err)
		return
	}
	log.Debugf("getMetadataClusterName: metadata = %+v", metadata)

	clusterName = metadata.ClusterName
	infraID = metadata.InfraID

	return
}

func updateBastionInformations(ctx context.Context, cloud string, bastionInformations []bastionInformation) (err error) {
	var (
		connCompute *gophercloud.ServiceClient
		allServers  []servers.Server
	)

	connCompute, err = NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return
	}
//	log.Debugf("updateBastionInformations: connCompute = %+v", connCompute)

	allServers, err = getAllServers(ctx, connCompute)
	if err != nil {
		return
	}
//	log.Debugf("updateBastionInformations: allServers = %+v", allServers)

	for i, bastionInformation := range bastionInformations {
		var (
			clusterName      string
			infraID          string
			bastionServer    servers.Server
			bastionIpAddress string
		)

		log.Debugf("updateBastionInformations: OLD bastionInformation = %+v", bastionInformation)

		bastionInformations[i].Valid = false

		// Refresh the data
		clusterName, infraID, err = getMetadataClusterName(bastionInformation.Metadata)
		if err != nil {
			errstr := strings.TrimSpace(err.Error())
			if !strings.HasSuffix(errstr, "no such file or directory") {
				return err
			}
			err = nil
			continue
		}

		bastionServer, err = findServerInList(allServers, clusterName)
		if err != nil {
			return
		}
		log.Debugf("updateBastionInformations: bastionServer.Name = %s", bastionServer.Name)

		_, bastionIpAddress, err = findIpAddress(bastionServer)
		log.Debugf("updateBastionInformations: bastionIpAddress = %s", bastionIpAddress)
		if err != nil || bastionIpAddress == "" {
			log.Debugf("ERROR: bastionIpAddress is EMPTY! (%v)", err)
			continue
		}

		currentVMs := 0
		previousVMs := bastionInformation.NumVMs
		for _, server := range allServers {
			if !strings.HasPrefix(strings.ToLower(server.Name), infraID) {
				continue
			}
			currentVMs++
		}
		log.Debugf("updateBastionInformations: currentVMs = %d, NumVMs = %d", currentVMs, bastionInformation.NumVMs)

		// The range operator creates a copy of the array.
		// We need to modify the original array!
		bastionInformations[i].Valid = true
		bastionInformations[i].ClusterName = bastionServer.Name
		bastionInformations[i].InfraID = infraID
		bastionInformations[i].IPAddress = bastionIpAddress
		bastionInformations[i].NumVMs = currentVMs

		log.Debugf("updateBastionInformations: NEW bastionInformation = %+v", bastionInformation)

		if previousVMs == 0 && currentVMs > 0 {
			// First time for this bastion
		}

		if currentVMs == 0 && previousVMs > 0 {
			// Last time for this bastion
		}
	}

	return
}

func getAllServers(ctx context.Context, connCompute *gophercloud.ServiceClient) (allServers []servers.Server, err error) {
	var (
		duration time.Duration
		pager    pagination.Page
	)

	backoff := wait.Backoff{
		Duration: 1 * time.Minute,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32,
	}

	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			err2     error
		)

		duration = leftInContext(ctx)
		log.Debugf("getAllServers: duration = %v, calling servers.List", duration)
		pager, err2 = servers.List(connCompute, nil).AllPages(ctx)
		if err2 != nil {
			log.Debugf("getAllServers: servers.List returned error %v", err2)
			return false, nil
		}
//		log.Debugf("getAllServers: pager = %+v", pager)

		allServers, err2 = servers.ExtractServers(pager)
		if err2 != nil {
			log.Debugf("getAllServers: servers.ExtractServers returned error %v", err2)
			return false, nil
		}
//		log.Debugf("getAllServers: allServers = %+v", allServers)

		return true, nil
	})

	return
}

func findServerInList(allServers []servers.Server, name string) (foundServer servers.Server, err error) {
	var (
		server servers.Server
	)

	for _, server = range allServers {
		if server.Name == name {
			foundServer = server
			return
		}
	}

	err = fmt.Errorf("Could not find server named %s", name)
	return
}

func getServerSet(allServers []servers.Server) sets.Set[string] {
	var (
		knownServers = sets.Set[string]{}
		server       servers.Server
	)

	for _, server = range allServers {
		if !slices.ContainsFunc(
			[]string{"bootstrap", "master", "worker"},
			func(s string) bool {
//				log.Debugf("strings.Contains(%s, %s) = %v", server.Name, s, strings.Contains(server.Name, s))
				return strings.Contains(server.Name, s)
			}) {
			continue
		}

		_, ipAddress, err := findIpAddress(server)
		if err != nil || ipAddress == "" {
			continue
		}

//		log.Debugf("Found new server %s", server.Name)
		knownServers.Insert(server.Name)
	}

	return knownServers
}

func findIpAddress(server servers.Server) (string, string, error) {
	var (
		subnetContents []interface {}
		mapSubNetwork  map[string]interface{}
		ok             bool
		ipAddress      string
	)

//	log.Debugf("server = %+v", server)

	for key := range server.Addresses {
//		log.Debugf("key = %+v", key)

		// Addresses:map[vlan1337:[map[OS-EXT-IPS-MAC:mac_addr:fa:16:3e:b1:33:03 OS-EXT-IPS:type:fixed addr:10.20.182.169 version:4]]]
		subnetContents, ok = server.Addresses[key].([]interface {})
		if !ok {
			return "", "", fmt.Errorf("Error: did not convert to [] of interface {}: %v", server.Addresses)
		}

		for _, subnetValue := range subnetContents {
//			log.Debugf("subnetValue = %+v", subnetValue)
//			log.Debugf("subnetValue = %+v", reflect.TypeOf(subnetValue))

			mapSubNetwork, ok = subnetValue.(map[string]interface{})
			if !ok {
				return "", "", fmt.Errorf("Error: did not convert to map[string] of interface {}: %v", server.Addresses)
			}

//			log.Debugf("mapSubNetwork = %+v", mapSubNetwork)

			macAddrI, ok := mapSubNetwork["OS-EXT-IPS-MAC:mac_addr"]
//			log.Debugf("macAddrI, ok = %+v, %v", macAddrI, ok)
			if !ok {
				return "", "", fmt.Errorf("Error: mapSubNetwork did not contain \"OS-EXT-IPS-MAC:mac_addr\": %v", mapSubNetwork)
			}
			macAddr, ok := macAddrI.(string)
//			log.Debugf("macAddr, ok = %+v, %v", macAddr, ok)
			if !ok {
				return "", "", fmt.Errorf("Error: macAddrI was not a string: %v", macAddrI)
			}

			ipAddressI, ok := mapSubNetwork["addr"]
//			log.Debugf("ipAddressI, ok = %+v, %v", ipAddressI, ok)
			if !ok {
				return "", "", fmt.Errorf("Error: mapSubNetwork did not contain \"addr\": %v", mapSubNetwork)
			}
			ipAddress, ok = ipAddressI.(string)
//			log.Debugf("ipAddress, ok = %+v, %v", ipAddress, ok)
			if !ok {
				return "", "", fmt.Errorf("Error: ipAddressI was not a string: %v", ipAddressI)
			}

			return macAddr, ipAddress, nil
		}
	}

	return "", "", nil
}

func dhcpdConf(ctx context.Context, filename string, cloud string, domainName string, dhcpSubnet string, dhcpNetmask string, dhcpRouter string, dhcpDnsServers string) error {
	var (
		connCompute *gophercloud.ServiceClient
		allServers  []servers.Server
		server      servers.Server
		file        *os.File
		err         error
	)

	connCompute, err = NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
//	log.Debugf("dhcpdConf: connCompute = %+v", connCompute)

	allServers, err = getAllServers(ctx, connCompute)
	if err != nil {
		return err
	}
//	log.Debugf("dhcpdConf: allServers = %+v", allServers)

	fmt.Printf("Writing %s\n\n", filename)

	err = os.Remove(filename)
	if err != nil {
		if !strings.HasSuffix(err.Error(), "no such file or directory") {
			return err
		}
	}

	file, err = os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	defer file.Close()

	fmt.Fprintf(file, "#\n")
	fmt.Fprintf(file, "# DHCP Server Configuration file.\n")
	fmt.Fprintf(file, "#   see /usr/share/doc/dhcp-server/dhcpd.conf.example\n")
	fmt.Fprintf(file, "#   see dhcpd.conf(5) man page\n")
	fmt.Fprintf(file, "#\n")
	fmt.Fprintf(file, "\n")
	fmt.Fprintf(file, "# Persist interface configuration when dhcpcd exits.\n")
	fmt.Fprintf(file, "persistent;\n")
	fmt.Fprintf(file, "\n")
	fmt.Fprintf(file, "default-lease-time 2678400;\n")
	fmt.Fprintf(file, "max-lease-time 2678400;\n")
	fmt.Fprintf(file, "\n")
	fmt.Fprintf(file, "subnet %s netmask %s {\n", dhcpSubnet, dhcpNetmask)
	fmt.Fprintf(file, "   interface env2;\n")
	fmt.Fprintf(file, "   option routers %s;\n", dhcpRouter)
	fmt.Fprintf(file, "   option subnet-mask %s;\n", dhcpSubnet)
	fmt.Fprintf(file, "   option domain-name-servers %s;\n", dhcpDnsServers)
	fmt.Fprintf(file, "   option domain-name \"%s\";\n", domainName)
	fmt.Fprintf(file, "   ignore unknown-clients;\n")
	fmt.Fprintf(file, "#  update-static-leases true;\n")
	fmt.Fprintf(file, "}\n")
	fmt.Fprintf(file, "\n")

	for _, server = range allServers {
//		log.Debugf("dhcpdConf: server = %+v", server)

		macAddr, ipAddress, err := findIpAddress(server)
		if err == nil && macAddr != "" && ipAddress != "" {
			fmt.Fprintf(file, "host %s {\n", server.Name)
			fmt.Fprintf(file, "    hardware ethernet    %s;\n", macAddr)
			fmt.Fprintf(file, "    fixed-address        %s;\n", ipAddress)
			fmt.Fprintf(file, "    max-lease-time       84600;\n")
			fmt.Fprintf(file, "    option host-name     \"%s\";\n", server.Name)
			fmt.Fprintf(file, "    ddns-hostname        %s;\n", server.Name)
			fmt.Fprintf(file, "}\n")
			fmt.Fprintf(file, "\n")
		}
	}

	return nil
}

func haproxyCfg(ctx context.Context, cloud string, bastionInformations []bastionInformation) error {
	var (
		connCompute *gophercloud.ServiceClient
		allServers  []servers.Server
		server      servers.Server
		err         error
	)

	connCompute, err = NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
//	log.Debugf("haproxyCfg: connCompute = %+v", connCompute)

	allServers, err = getAllServers(ctx, connCompute)
	if err != nil {
		return err
	}
//	log.Debugf("haproxyCfg: allServers = %+v", allServers)

	log.Debugf("haproxyCfg: len(bastionInformations) = %d", len(bastionInformations))
	if len(bastionInformations) == 0 {
		fmt.Printf("Warning: no bastion servers found!")
		return nil
	}

	for _, bastionInformation := range bastionInformations {
		var (
			file        *os.File
			filename    string
			prefixMatch string
		)

		log.Debugf("haproxyCfg: bastionInformation = %+v", bastionInformation)

		if !bastionInformation.Valid {
			continue
		}

		filename = "/tmp/haproxy.cfg"
		fmt.Printf("Writing %s\n\n", filename)

		err = os.Remove(filename)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "no such file or directory") {
				return err
			}
		}

		file, err = os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		defer file.Close()

		fmt.Fprintf(file, "#\n")
		fmt.Fprintf(file, "global\n")
		fmt.Fprintf(file, "daemon\n")
		fmt.Fprintf(file, "\n")
		fmt.Fprintf(file, "defaults\n")
		fmt.Fprintf(file, "log global\n")
		fmt.Fprintf(file, "timeout connect 5s\n")
		fmt.Fprintf(file, "timeout client 50s\n")
		fmt.Fprintf(file, "timeout server 50s\n")
		fmt.Fprintf(file, "\n")
		fmt.Fprintf(file, "listen stats # Define a listen section called \"stats\"\n")
		fmt.Fprintf(file, "  bind :9000 # Listen on localhost:9000\n")
		fmt.Fprintf(file, "  mode http\n")
		fmt.Fprintf(file, "  stats enable  # Enable stats page\n")
		fmt.Fprintf(file, "  stats hide-version  # Hide HAProxy version\n")
		fmt.Fprintf(file, "  stats realm Haproxy\\ Statistics  # Title text for popup window\n")
		fmt.Fprintf(file, "  stats uri /haproxy_stats  # Stats URI\n")
		fmt.Fprintf(file, "  stats auth Username:Password  # Authentication credentials\n")
		fmt.Fprintf(file, "\n")

		// listen ingress-http
		fmt.Fprintf(file, "listen ingress-http\n")
		fmt.Fprintf(file, "bind *:80\n")
		fmt.Fprintf(file, "mode tcp\n")
		prefixMatch = fmt.Sprintf("%s-worker-", bastionInformation.InfraID)
		for _, server = range allServers {
			if !strings.HasPrefix(strings.ToLower(server.Name), prefixMatch) {
				continue
			}
	
			macAddr, ipAddress, err := findIpAddress(server)
			if err == nil && macAddr != "" && ipAddress != "" {
				fmt.Fprintf(file, "server %s %s:80 check\n", server.Name, ipAddress)
			}
		}
		fmt.Fprintf(file, "\n")

		// listen ingress-https
		fmt.Fprintf(file, "listen ingress-https\n")
		fmt.Fprintf(file, "bind *:443\n")
		fmt.Fprintf(file, "mode tcp\n")
		prefixMatch = fmt.Sprintf("%s-worker-", bastionInformation.InfraID)
		for _, server = range allServers {
			if !strings.HasPrefix(strings.ToLower(server.Name), prefixMatch) {
				continue
			}

			macAddr, ipAddress, err := findIpAddress(server)
			if err == nil && macAddr != "" && ipAddress != "" {
				fmt.Fprintf(file, "server %s %s:443 check\n", server.Name, ipAddress)
			}
		}
		fmt.Fprintf(file, "\n")

		// listen api
		fmt.Fprintf(file, "listen api\n")
		fmt.Fprintf(file, "bind *:6443\n")
		fmt.Fprintf(file, "mode tcp\n")
		for _, server = range allServers {
			if !strings.HasPrefix(strings.ToLower(server.Name), bastionInformation.InfraID) {
				continue
			}
			if !(strings.Contains(strings.ToLower(server.Name), "bootstrap") || strings.Contains(strings.ToLower(server.Name), "master")) {
				continue
			}

			macAddr, ipAddress, err := findIpAddress(server)
			if err == nil && macAddr != "" && ipAddress != "" {
				fmt.Fprintf(file, "server %s %s:6443 check\n", server.Name, ipAddress)
			}
		}
		fmt.Fprintf(file, "\n")

		// listen machine-config-server
		fmt.Fprintf(file, "listen machine-config-server\n")
		fmt.Fprintf(file, "bind *:22623\n")
		fmt.Fprintf(file, "mode tcp\n")
		for _, server = range allServers {
			if !strings.HasPrefix(strings.ToLower(server.Name), bastionInformation.InfraID) {
				continue
			}
			if !(strings.Contains(strings.ToLower(server.Name), "bootstrap") || strings.Contains(strings.ToLower(server.Name), "master")) {
				continue
			}

			macAddr, ipAddress, err := findIpAddress(server)
			if err == nil && macAddr != "" && ipAddress != "" {
				fmt.Fprintf(file, "server %s %s:22623 check\n", server.Name, ipAddress)
			}
		}

		err = runSplitCommand([]string{
			"scp",
			"-i",
			bastionInformation.InstallerRsa,
			filename,
			fmt.Sprintf("%s@%s:/etc/haproxy/haproxy.cfg", bastionInformation.Username, bastionInformation.IPAddress),
		})
		if err != nil {
			return err
		}

		err = runSplitCommand([]string{
			"ssh",
			"-i",
			bastionInformation.InstallerRsa,
			fmt.Sprintf("%s@%s", bastionInformation.Username, bastionInformation.IPAddress),
			"sudo",
			"systemctl",
			"restart",
			"haproxy.service",
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func getClusterName(allServers []servers.Server) (clusterName string) {
	var (
		server servers.Server
	)

	for _, server = range allServers {
//		log.Debugf("getClusterName: server.Name = %s", server.Name)

		idx := strings.Index(server.Name, "-bootstrap")
//		log.Debugf("getClusterName: idx = %d", idx)
		if idx < 0 {
			idx = strings.Index(server.Name, "-master")
//			log.Debugf("getClusterName: idx = %d", idx)
		}
		if idx < 0 {
			continue
		}

		clusterName = server.Name[0:idx-1]
//		log.Debugf("getClusterName: clusterName = %s", clusterName)

		idx = strings.LastIndex(clusterName, "-")
//		log.Debugf("getClusterName: idx = %d", idx)
		if idx < 0 {
			continue
		}

		clusterName = clusterName[0:idx]
//		log.Debugf("getClusterName: clusterName = %s", clusterName)
		break
	}

	return
}

var (
	firstDnsRun = true
)

func dnsRecords(ctx context.Context, cloud string, apiKey string, domainName string, bastionInformations []bastionInformation, knownServers sets.Set[string], addedServerSet sets.Set[string], deletedServerSet sets.Set[string]) error {
	var (
		dnsService    *dnsrecordsv1.DnsRecordsV1
		cisServiceID  string
		crnstr        string
		zoneID        string
		connCompute   *gophercloud.ServiceClient
		allServers    []servers.Server
		server        servers.Server
		clusterName   string
		err           error
	)

	if apiKey == "" {
		log.Debugf("dnsRecords: WARNING: apiKey not specified, aborting!")
		return nil
	}

	cisServiceID, _, err = getServiceInfo(ctx, apiKey, "internet-svcs", "")
	if err != nil {
		log.Errorf("getServiceInfo returns %v", err)
		return err
	}
	log.Debugf("dnsRecords: cisServiceID = %s", cisServiceID)

	crnstr, zoneID, err = getDomainCrn(ctx, apiKey, cisServiceID, domainName)
	log.Debugf("dnsRecords: crnstr = %s, zoneID = %s, err = %+v", crnstr, zoneID, err)
	if err != nil {
		log.Errorf("getDomainCrn returns %v", err)
		return err
	}

	dnsService, err = loadDnsServiceAPI(apiKey, crnstr, zoneID)
	if err != nil {
		return err
	}
	log.Debugf("dnsRecords: dnsService = %+v", dnsService)

	connCompute, err = NewServiceClient(ctx, "compute", DefaultClientOpts(cloud))
	if err != nil {
		return err
	}
//	log.Debugf("dnsRecords: connCompute = %+v", connCompute)

	allServers, err = getAllServers(ctx, connCompute)
	if err != nil {
		return err
	}
//	log.Debugf("dnsRecords: allServers = %+v", allServers)

	clusterName = getClusterName(allServers)
	log.Debugf("dnsRecords: clusterName = %s", clusterName)
	if clusterName == "" {
		return nil
	}

	if firstDnsRun {
		log.Debugf("dnsRecords: FIRST DNS RUN!")

		firstDnsRun = false

		for _, bastionInformation := range bastionInformations {
			if !bastionInformation.Valid {
				continue
			}

			err = createOrDeletePublicDNSRecord(ctx,
				dnsrecordsv1.CreateDnsRecordOptions_Type_A,
				fmt.Sprintf("api.%s.%s", bastionInformation.ClusterName, domainName),
				bastionInformation.IPAddress,
				true,
				dnsService)
			err = createOrDeletePublicDNSRecord(ctx,
				dnsrecordsv1.CreateDnsRecordOptions_Type_A,
				fmt.Sprintf("api-int.%s.%s", bastionInformation.ClusterName, domainName),
				bastionInformation.IPAddress,
				true,
				dnsService)
			err = createOrDeletePublicDNSRecord(ctx,
				dnsrecordsv1.CreateDnsRecordOptions_Type_Cname,
				fmt.Sprintf("*.apps.%s.%s", bastionInformation.ClusterName, domainName),
				fmt.Sprintf("api.%s.%s", bastionInformation.ClusterName, domainName),
				true,
				dnsService)
		}
	}

	for deletedServer := range deletedServerSet {
		log.Debugf("dnsRecords: deletedServer = %s", deletedServer)

		if slices.ContainsFunc(
			[]string{"bootstrap", "master", "worker"},
			func(s string) bool {
//				log.Debugf("strings.Contains(%s, %s) = %v", deletedServer, s, strings.Contains(deletedServer, s))
				return strings.Contains(deletedServer, s)
			}) {
			err = createOrDeletePublicDNSRecord(ctx,
				dnsrecordsv1.CreateDnsRecordOptions_Type_A,
				fmt.Sprintf("%s.%s", deletedServer, domainName),
				"",
				false,
				dnsService)
		}
	}

	for addedServer := range addedServerSet {
		log.Debugf("dnsRecords: addedServer = %s", addedServer)

		for _, server = range allServers {
			if server.Name != addedServer {
				continue
			}

			_, ipAddress, err := findIpAddress(server)
			if err != nil || ipAddress == "" {
				continue
			}

			if slices.ContainsFunc(
				[]string{"bootstrap", "master", "worker"},
				func(s string) bool {
//					log.Debugf("strings.Contains(%s, %s) = %v", server.Name, s, strings.Contains(server.Name, s))
					return strings.Contains(server.Name, s)
				}) {
				err = createOrDeletePublicDNSRecord(ctx,
					dnsrecordsv1.CreateDnsRecordOptions_Type_A,
					fmt.Sprintf("%s.%s", server.Name, domainName),
					ipAddress,
					true,
					dnsService)
			}
		}
	}

	if len(knownServers) == 0 && !firstDnsRun {
		firstDnsRun = false

		for _, bastionInformation := range bastionInformations {
			if !bastionInformation.Valid {
				continue
			}

			err = createOrDeletePublicDNSRecord(ctx,
				dnsrecordsv1.CreateDnsRecordOptions_Type_A,
				fmt.Sprintf("api.%s.%s", bastionInformation.ClusterName, domainName),
				"",
				false,
				dnsService)
			err = createOrDeletePublicDNSRecord(ctx,
				dnsrecordsv1.CreateDnsRecordOptions_Type_A,
				fmt.Sprintf("api-int.%s.%s", bastionInformation.ClusterName, domainName),
				"",
				false,
				dnsService)
			err = createOrDeletePublicDNSRecord(ctx,
				dnsrecordsv1.CreateDnsRecordOptions_Type_Cname,
				fmt.Sprintf("*.apps.%s.%s", bastionInformation.ClusterName, domainName),
				fmt.Sprintf("api.%s.%s", bastionInformation.ClusterName, domainName),
				false,
				dnsService)
		}
	}

	return nil
}

func loadResourceControllerAPI(apiKey string) (controllerAPI *resourcecontrollerv2.ResourceControllerV2, err error) {
	controllerAPI, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
	})

	return
}

func loadDnsServiceAPI(apiKey string, crnstr string, zoneID string)(service *dnsrecordsv1.DnsRecordsV1, err error) {
	service, err = dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{
		Authenticator:  &core.IamAuthenticator{
			ApiKey: apiKey,
		},
		Crn:            &crnstr,
		ZoneIdentifier: &zoneID,
	})

	return
}

// getServiceInfo retrieving id info of given service and service plan
func getServiceInfo(ctx context.Context, apiKey string, service string, servicePlan string) (string, string, error) {
	var (
		serviceID     string
		servicePlanID string
	)

	gcv1, err := globalcatalogv1.NewGlobalCatalogV1(&globalcatalogv1.GlobalCatalogV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
		URL:           globalcatalogv1.DefaultServiceURL,
	})
	log.Debugf("getServiceInfo: gcv1 = %+v", gcv1)
	if err != nil {
		return "", "", err
	}

	if gcv1 == nil {
		return "", "", fmt.Errorf("unable to get global catalog")
	}

	// TO-DO need to explore paging for catalog list since ListCatalogEntriesOptions does not take start
	include := "*"
	listCatalogEntriesOpt := globalcatalogv1.ListCatalogEntriesOptions{Include: &include, Q: &service}
	catalogEntriesList, _, err := gcv1.ListCatalogEntriesWithContext(ctx, &listCatalogEntriesOpt)
	if err != nil {
		return "", "", err
	}
	if catalogEntriesList != nil {
		for _, catalog := range catalogEntriesList.Resources {
			log.Debugf("getServiceInfo: catalog.Name = %s, catalog.ID = %s", *catalog.Name, *catalog.ID)
			if *catalog.Name == service {
				serviceID = *catalog.ID
			}
		}
	}

	if serviceID == "" {
		return "", "", fmt.Errorf("could not retrieve service id for service %s", service)
	} else if servicePlan == "" {
		return serviceID, "", nil
	}

	kind := "plan"
	getChildOpt := globalcatalogv1.GetChildObjectsOptions{
		ID: &serviceID,
		Kind: &kind,
	}

	var childObjResult *globalcatalogv1.EntrySearchResult

	childObjResult, _, err = gcv1.GetChildObjectsWithContext(ctx, &getChildOpt)
	if err != nil {
		return "", "", err
	}

	for _, plan := range childObjResult.Resources {
		if *plan.Name == servicePlan {
			servicePlanID = *plan.ID
			return serviceID, servicePlanID, nil
		}
	}

	err = fmt.Errorf("could not retrieve plan id for service name: %s & service plan name: %s", service, servicePlan)

	return "", "", err
}

func getDomainCrn(ctx context.Context, apiKey string, cisServiceID string, baseDomain string) (crnstr string, zoneID string, err error) {
	var (
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L4525-L4534
		resources *resourcecontrollerv2.ResourceInstancesList
		perPage   int64 = 64
		moreData        = true
		zv1       *zonesv1.ZonesV1
		zoneList  *zonesv1.ListZonesResp
	)

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err := resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
		URL:           resourcecontrollerv2.DefaultServiceURL,
	})
	log.Debugf("getDomainCrn: controllerSvc = %+v", controllerSvc)
	if err != nil {
		err = fmt.Errorf("NewResourceControllerV2 failed with: %v", err)
		return
	}

	listResourceOptions := resourcecontrollerv2.ListResourceInstancesOptions{
		ResourceID: &cisServiceID,
		Limit:      &perPage,
	}
	log.Debugf("getDomainCrn: listResourceOptions = %+v", listResourceOptions)

	for moreData {
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L5008
		resources, _, err = controllerSvc.ListResourceInstancesWithContext(ctx, &listResourceOptions)
		if err != nil {
			err = fmt.Errorf("ListResourceInstancesWithContext failed with: %v", err)
			return
		}
		log.Debugf("getDomainCrn: RowsCount %v", *resources.RowsCount)

		for _, instance := range resources.Resources {
			log.Debugf("getDomainCrn: instance.Name = %s, instance.CRN = %s", *instance.Name, *instance.CRN)

			zv1, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
				Authenticator: &core.IamAuthenticator{
					ApiKey: apiKey,
				},
				Crn:           instance.CRN,
			})
			log.Debugf("getDomainCrn: zv1 = %+v", zv1)
			if err != nil {
				err = fmt.Errorf("NewZonesV1 failed with: %v", err)
				return
			}

			zoneList, _, err = zv1.ListZonesWithContext(ctx, &zonesv1.ListZonesOptions{})
			if err != nil {
				err = fmt.Errorf("ListZonesWithContext failed with: %v", err)
				return
			}
			if zoneList == nil {
				err = fmt.Errorf("zoneList is nil")
				return
			}

			for _, zone := range zoneList.Result {
				log.Debugf("getDomainCrn: zone.Name = %s, zone.ID = %s", *zone.Name, *zone.ID)
				if *zone.Name == baseDomain {
					crnstr = *instance.CRN
					zoneID  = *zone.ID
					err = nil
					return
				}
			}
		}

		if resources.NextURL != nil {
			var start *string

			start, err = resources.GetNextStart()
			if err != nil {
				log.Debugf("getDomainCrn: err = %v", err)
				err = fmt.Errorf("failed to GetNextStart: %v", err)
				return
			}
			if start != nil {
				log.Debugf("getDomainCrn: start = %v", *start)
				listResourceOptions.SetStart(*start)
			}
		} else {
			log.Debugf("getDomainCrn: NextURL = nil")
			moreData = false
		}
	}

	err = fmt.Errorf("failed to find %s", baseDomain)
	return
}

func findDNSRecord(ctx context.Context, dnsService *dnsrecordsv1.DnsRecordsV1, cname string)(foundID string, content string, err error) {
	var (
		listOptions *dnsrecordsv1.ListAllDnsRecordsOptions
		records     *dnsrecordsv1.ListDnsrecordsResp
		response    *core.DetailedResponse
	)

	log.Debugf("findDNSRecord: cname = %s", cname)

	listOptions = dnsService.NewListAllDnsRecordsOptions()
	listOptions.SetName(cname)
//	log.Debugf("findDNSRecord: listOptions = %+v", listOptions)

	records, response, err = dnsService.ListAllDnsRecordsWithContext(ctx, listOptions)
	if err != nil {
		err = fmt.Errorf("ListAllDnsRecordsWithContext response = %+v, err = %+v", response, err)
		return
	}
//	log.Debugf("findDNSRecord: records = %+v", records)

	log.Debugf("findDNSRecord: len(records.Result) = %d", len(records.Result))
	for _, record := range records.Result {
		log.Debugf("findDNSRecord: record.Name = %s, record.ID = %s", *record.Name, *record.ID)

		if cname == *record.Name {
			foundID = *record.ID
			content = *record.Content
			return
		}
	}

	return
}

func createOrDeletePublicDNSRecord(ctx context.Context, dnsRecordType string, hostname string, cname string, shouldCreate bool, dnsService *dnsrecordsv1.DnsRecordsV1) error {
	var (
		foundRecordID string
		content       string
		deleteOptions *dnsrecordsv1.DeleteDnsRecordOptions
		createOptions *dnsrecordsv1.CreateDnsRecordOptions
		err           error
	)

	log.Debugf("createOrDeletePublicDNSRecord: dnsRecordType = %s, hostname = %s, cname = %s, shouldCreate = %v", dnsRecordType, hostname, cname, shouldCreate)

	foundRecordID, content, err = findDNSRecord(ctx, dnsService, hostname)
	if err != nil {
		return err
	}
	log.Debugf("createOrDeletePublicDNSRecord: foundRecordID = %s, content = %s", foundRecordID, content)

	// Does it already exist?
	if foundRecordID != "" {
		log.Debugf("createOrDeletePublicDNSRecord: !shouldCreate = %v, (content != cname && shouldCreate) = %v", !shouldCreate, (content != cname && shouldCreate))

		// If we should delete OR we are creating and the contents are different?
		if (!shouldCreate || (content != cname && shouldCreate)) {
			deleteOptions = dnsService.NewDeleteDnsRecordOptions(foundRecordID)
			log.Debugf("createOrDeletePublicDNSRecord: deleteOptions = %+v", deleteOptions)

			result, response, err := dnsService.DeleteDnsRecordWithContext(ctx, deleteOptions)
			if err != nil {
				return fmt.Errorf("DeleteDnsRecordWithContext response = %+v, err = %+v", response, err)
			}

			if !*result.Success {
				for _, aerrmsg := range result.Errors {
					log.Debugf("createOrDeletePublicDNSRecord: aerrmsg = %+v", aerrmsg)
					// @TODO
				}
				return fmt.Errorf("DeleteDnsRecordWithContext result.Success is false")
			}
		}

		// If we shoud create AND the content is the same, then we are done.
		if shouldCreate && (content == cname) {
			log.Debugf("createOrDeletePublicDNSRecord: content already exists!")
			return nil
		}
	}

	if !shouldCreate {
		return nil
	}

	createOptions = dnsService.NewCreateDnsRecordOptions()
	createOptions.SetType(dnsRecordType)
	createOptions.SetName(hostname)
	createOptions.SetContent(cname)
	createOptions.SetTTL(60)
	log.Debugf("createOrDeletePublicDNSRecord: createOptions = %+v", createOptions)

	result, response, err := dnsService.CreateDnsRecord(createOptions)
	if err != nil {
		log.Errorf("dnsRecordService.CreateDnsRecord returns %v", err)
		return err
	}
	log.Debugf("createOrDeletePublicDNSRecord: Result.ID = %v, RawResult = %v", *result.Result.ID, response.RawResult)

	return nil
}
