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
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"strings"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/pagination"

	"github.com/IBM/networking-go-sdk/dnsrecordsv1"

	"github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/utils/ptr"
)

const (
	bastionIpFilename = "/tmp/bastionIp"
)

func createBastionCommand(createBastionFlags *flag.FlagSet, args []string) error {
	var (
		out            io.Writer
		apiKey         string
		ptrCloud       *string
		ptrBastionName *string
		ptrFlavorName  *string
		ptrImageName   *string
		ptrNetworkName *string
		ptrSshKeyName  *string
		ptrDomainName  *string
		ptrShouldDebug *string
		ctx            context.Context
		cancel         context.CancelFunc
		foundServer    servers.Server
		err            error
	)

	// NOTE: This is optional
	apiKey = os.Getenv("IBMCLOUD_API_KEY")

	ptrCloud = createBastionFlags.String("cloud", "", "The cloud to use in clouds.yaml")
	ptrBastionName = createBastionFlags.String("bastionName", "", "The name of the bastion VM to use")
	ptrFlavorName = createBastionFlags.String("flavorName", "", "The name of the flavor to use")
	ptrImageName = createBastionFlags.String("imageName", "", "The name of the image to use")
	ptrNetworkName = createBastionFlags.String("networkName", "", "The name of the network to use")
	ptrSshKeyName = createBastionFlags.String("sshKeyName", "", "The name of the ssh keypair to use")
	// NOTE: This is optional
	ptrDomainName = createBastionFlags.String("domainName", "", "The DNS domain to use")
	ptrShouldDebug = createBastionFlags.String("shouldDebug", "false", "Should output debug output")

	createBastionFlags.Parse(args)

	if ptrCloud == nil || *ptrCloud == "" {
		return fmt.Errorf("Error: --cloud not specified")
	}
	if ptrBastionName == nil || *ptrBastionName == "" {
		return fmt.Errorf("Error: --bastionName not specified")
	}
	if ptrFlavorName == nil || *ptrFlavorName == "" {
		return fmt.Errorf("Error: --flavorName not specified")
	}
	if ptrImageName == nil || *ptrImageName == "" {
		return fmt.Errorf("Error: --imageName not specified")
	}
	if ptrNetworkName == nil || *ptrNetworkName == "" {
		return fmt.Errorf("Error: --networkName not specified")
	}
	if ptrSshKeyName == nil || *ptrSshKeyName == "" {
		return fmt.Errorf("Error: --sshKeyName not specified")
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

	ctx, cancel = context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	err = os.Remove(bastionIpFilename)
	if err != nil {
		errstr := strings.TrimSpace(err.Error())
		if !strings.HasSuffix(errstr, "no such file or directory") {
			return err
		}
	}

	foundServer, err = findServer(ctx, *ptrCloud, *ptrBastionName)
//	log.Debugf("foundServer = %+v", foundServer)
	if err != nil {
		if strings.HasPrefix(err.Error(), "Could not find server named") {
			fmt.Printf("Could not find server %s, creating...\n", *ptrBastionName)

			err = createServer(ctx,
				*ptrCloud,
				*ptrFlavorName,
				*ptrImageName,
				*ptrNetworkName,
				*ptrSshKeyName,
				*ptrBastionName,
				nil,
			)
			if err != nil {
				return err
			}

			fmt.Println("Done!")

			foundServer, err = findServer(ctx, *ptrCloud, *ptrBastionName)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	err = setupBastionServer(ctx, *ptrCloud, foundServer)
	if err != nil {
		return err
	}

	if apiKey != "" {
		err = dnsForServer(ctx, *ptrCloud, apiKey, *ptrBastionName, *ptrDomainName)
		if err != nil {
			return err
		}
	} else {
		fmt.Println("Warning: IBMCLOUD_API_KEY not set.  Make sure DNS is supported via another way.")
	}

	return err
}

func createServer(ctx context.Context, cloudName string, flavorName string, imageName string, networkName string, sshKeyName string, bastionName string, userData []byte) error {
	var (
		flavor           flavors.Flavor
		image            images.Image
		network          networks.Network
		sshKeyPair       keypairs.KeyPair
		builder          ports.CreateOptsBuilder
		portCreateOpts   ports.CreateOpts
		portList         []servers.Network
		serverCreateOpts servers.CreateOptsBuilder
		newServer        *servers.Server
		err              error
	)

	flavor, err = findFlavor(ctx, cloudName, flavorName)
	if err != nil {
		return err
	}
	log.Debugf("flavor = %+v", flavor)

	image, err = findImage(ctx, cloudName, imageName)
	if err != nil {
		return err
	}
	log.Debugf("image = %+v", image)

	network, err = findNetwork(ctx, cloudName, networkName)
	if err != nil {
		return err
	}
	log.Debugf("network = %+v", network)

	if sshKeyName != "" {
		sshKeyPair, err = findKeyPair(ctx, cloudName, sshKeyName)
		if err != nil {
			return err
		}
	}

	connNetwork, err := NewServiceClient(ctx, "network", DefaultClientOpts(cloudName))
	if err != nil {
		return err
	}
	fmt.Printf("connNetwork = %+v\n", connNetwork)

	portCreateOpts = ports.CreateOpts{
		Name:                  fmt.Sprintf("%s-port", bastionName),
		NetworkID:		network.ID,
		Description:           "hamzy test",
		AdminStateUp:          nil,
		MACAddress:            ptr.Deref(nil, ""),
		AllowedAddressPairs:   nil,
		ValueSpecs:            nil,
		PropagateUplinkStatus: nil,
	}

	builder = portCreateOpts
	log.Debugf("builder = %+v\n", builder)

	port, err := ports.Create(ctx, connNetwork, builder).Extract()
	if err != nil {
		return err
	}
	log.Debugf("port = %+v\n", port)
	log.Debugf("port.ID = %v\n", port.ID)

	connCompute, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloudName))
	if err != nil {
		return err
	}
	fmt.Printf("connCompute = %+v\n", connCompute)

	portList = []servers.Network{
		{ Port: port.ID, },
	}

	serverCreateOpts = servers.CreateOpts{
		AvailabilityZone: "s1022",
		FlavorRef:        flavor.ID,
		ImageRef:         image.ID,
		Name:             bastionName,
		Networks:         portList,
		UserData:         userData,
		// Additional properties are not allowed ('tags' was unexpected)
//		Tags:             tags[:],
//              KeyName:          "",
//
//		Metadata:         instanceSpec.Metadata,
//		ConfigDrive:      &instanceSpec.ConfigDrive,
//		BlockDevice:      blockDevices,
	}
	log.Debugf("serverCreateOpts = %+v\n", serverCreateOpts)

	if sshKeyName != "" {
		newServer, err = servers.Create(ctx,
			connCompute,
			keypairs.CreateOptsExt{
				CreateOptsBuilder: serverCreateOpts,
				KeyName:           sshKeyPair.Name,
			},
			nil).Extract()
	} else {
		newServer, err = servers.Create(ctx, connCompute, serverCreateOpts, nil).Extract()
	}
	if err != nil {
		return err
	}
	log.Debugf("newServer = %+v\n", newServer)

	err = waitForServer(ctx, cloudName, bastionName)
	log.Debugf("waitForServer = %v\n", err)
	if err != nil {
		return err
	}

	return err
}

func setupBastionServer(ctx context.Context, cloudName string, server servers.Server) error {
	var (
		ipAddress    string
		homeDir      string
		installerRsa string
		outb         []byte
		outs         string
		exitError    *exec.ExitError
		err          error
	)

	log.Debugf("setupBastionServer: server = %+v", server)

	_, ipAddress, err = findIpAddress(server)
	if err != nil {
		return err
	}
	if ipAddress == "" {
		return fmt.Errorf("ip address is empty for server %s", server.Name)
	}

	log.Debugf("setupBastionServer: ipAddress = %s", ipAddress)

	homeDir, err = os.UserHomeDir()
	if err != nil {
		return err
	}
	log.Debugf("setupBastionServer: homeDir = %s", homeDir)

	installerRsa = path.Join(homeDir, ".ssh/id_installer_rsa")
	log.Debugf("setupBastionServer: installerRsa = %s", installerRsa)

	outb, err = runSplitCommand2([]string{
		"ssh-keygen",
		"-H",
		"-F",
		ipAddress,
	})
	outs = strings.TrimSpace(string(outb))
	log.Debugf("setupBastionServer: outs = \"%s\"", outs)
	if errors.As(err, &exitError) {
		log.Debugf("setupBastionServer: exitError.ExitCode() = %+v\n", exitError.ExitCode())

		log.Debugf("setupBastionServer: %v", exitError.ExitCode() == 1)
		if exitError.ExitCode() == 1 {

			outb, err = keyscanServer(ctx, ipAddress)
			if err != nil {
				return err
			}

			knownHosts := path.Join(homeDir, ".ssh/known_hosts")
			log.Debugf("setupBastionServer: knownHosts = %s", knownHosts)

			fileKnownHosts, err := os.OpenFile(knownHosts, os.O_APPEND|os.O_RDWR, 0644)
			if err != nil {
				return err
			}

			fileKnownHosts.Write(outb)

			defer fileKnownHosts.Close()
		}
	}

	fmt.Printf("Setting up server %s...\n", server.Name)

	outb, err = runSplitCommand2([]string{
		"ssh",
		"-i",
		installerRsa,
		fmt.Sprintf("cloud-user@%s", ipAddress),
		"rpm",
		"-q",
		"haproxy",
	})
	outs = strings.TrimSpace(string(outb))
	log.Debugf("setupBastionServer: outs = \"%s\"", outs)
	if errors.As(err, &exitError) {
		log.Debugf("setupBastionServer: exitError.ExitCode() = %+v\n", exitError.ExitCode())

		if exitError.ExitCode() == 1 && outs == "package haproxy is not installed" {
			outb, err = runSplitCommand2([]string{
				"ssh",
				"-i",
				installerRsa,
				fmt.Sprintf("cloud-user@%s", ipAddress),
				"sudo",
				"dnf",
				"install",
				"-y",
				"haproxy",
			})
			outs = strings.TrimSpace(string(outb))
			log.Debugf("setupBastionServer: outs = %s", outs)
			log.Debugf("setupBastionServer: err = %+v", err)
		}
	} else if err != nil {
		log.Debugf("setupBastionServer: err = %+v", err)
		return err
	}

	outb, err = runSplitCommand2([]string{
		"ssh",
		"-i",
		installerRsa,
		fmt.Sprintf("cloud-user@%s", ipAddress),
		"sudo",
		"stat",
		"-c",
		"%a",
		"/etc/haproxy/haproxy.cfg",
	})
	outs = strings.TrimSpace(string(outb))
	log.Debugf("setupBastionServer: outb = \"%s\"", outs)
	if err != nil {
		log.Debugf("setupBastionServer: err = %+v", err)
		return err
	}
	if outs != "646" {
		outb, err = runSplitCommand2([]string{
			"ssh",
			"-i",
			installerRsa,
			fmt.Sprintf("cloud-user@%s", ipAddress),
			"sudo",
			"chmod",
			"646",
			"/etc/haproxy/haproxy.cfg",
		})
		outs = strings.TrimSpace(string(outb))
		log.Debugf("setupBastionServer: outb = \"%s\"", outs)
		if err != nil {
			log.Debugf("setupBastionServer: err = %+v", err)
			return err
		}
	}

	outb, err = runSplitCommand2([]string{
		"ssh",
		"-i",
		installerRsa,
		fmt.Sprintf("cloud-user@%s", ipAddress),
		"sudo",
		"getsebool",
		"haproxy_connect_any",
	})
	outs = strings.TrimSpace(string(outb))
	log.Debugf("setupBastionServer: outb = \"%s\"", outs)
	if err != nil {
		log.Debugf("setupBastionServer: err = %+v", err)
		return err
	}
	if outs != "haproxy_connect_any --> on" {
		outb, err = runSplitCommand2([]string{
			"ssh",
			"-i",
			installerRsa,
			fmt.Sprintf("cloud-user@%s", ipAddress),
			"sudo",
			"setsebool",
			"-P",
			"haproxy_connect_any=1",
		})
		outs = strings.TrimSpace(string(outb))
		log.Debugf("setupBastionServer: outb = \"%s\"", outs)
		if err != nil {
			log.Debugf("setupBastionServer: err = %+v", err)
			return err
		}
	}

	fileBastionIp, err := os.OpenFile(bastionIpFilename, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	fileBastionIp.Write([]byte(ipAddress))

	defer fileBastionIp.Close()

	outb, err = runSplitCommand2([]string{
		"ssh",
		"-i",
		installerRsa,
		fmt.Sprintf("cloud-user@%s", ipAddress),
		"sudo",
		"systemctl",
		"enable",
		"haproxy.service",
	})
	outs = strings.TrimSpace(string(outb))
	log.Debugf("setupBastionServer: outb = \"%s\"", outs)
	if err != nil {
		log.Debugf("setupBastionServer: err = %+v", err)
		return err
	}

	outb, err = runSplitCommand2([]string{
		"ssh",
		"-i",
		installerRsa,
		fmt.Sprintf("cloud-user@%s", ipAddress),
		"sudo",
		"systemctl",
		"start",
		"haproxy.service",
	})
	outs = strings.TrimSpace(string(outb))
	log.Debugf("setupBastionServer: outb = \"%s\"", outs)
	if err != nil {
		log.Debugf("setupBastionServer: err = %+v", err)
		return err
	}

	return err
}

func removeCommentLines(input string) string {
	var (
		inputLines  []string
		resultLines []string
	)

	log.Debugf("removeCommentLines: input = \"%s\"", input)

	inputLines = strings.Split(input, "\n")

	for _, line := range inputLines {
		if !strings.HasPrefix(line, "#") {
			resultLines = append(resultLines, line)
		}
	}

	log.Debugf("removeCommentLines: resultLines = \"%s\"", resultLines)

	return strings.Join(resultLines, "\n")
}

func keyscanServer(ctx context.Context, ipAddress string) ([]byte, error) {
	var (
		outb []byte
		outs string
		err  error
	)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32,
	}

	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			err2 error
		)

		outb, err2 = runSplitCommandNoErr([]string{
			"ssh-keyscan",
			ipAddress,
		})
		outs = strings.TrimSpace(string(outb))
		log.Debugf("keyscanServer: outs = %s", outs)
		if err2 != nil {
			return false, nil
		}

		return true, nil
	})

	if err == nil {
		// Get rid of the comment lines generated by ssh-keyscan
		outLines := removeCommentLines(outs)
		outb = []byte(outLines)
	}

	return outb, err
}

func findFlavor(ctx context.Context, cloudName string, name string) (foundFlavor flavors.Flavor, err error) {
	var (
		pager      pagination.Page
		allFlavors []flavors.Flavor
		flavor     flavors.Flavor
	)

	connCompute, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloudName))
	if err != nil {
		return
	}
	fmt.Printf("findFlavor: connCompute = %+v\n", connCompute)

	pager, err = flavors.ListDetail(connCompute, flavors.ListOpts{}).AllPages(ctx)
	if err != nil {
		return
	}
//	log.Debugf("findFlavor: pager = %+v", pager)

	allFlavors, err = flavors.ExtractFlavors(pager)
	if err != nil {
		return
	}
//	log.Debugf("findFlavor: allFlavors = %+v", allFlavors)

	for _, flavor = range allFlavors {
//		log.Debugf("findFlavor: flavor.Name = %s, flavor.ID = %s", flavor.Name, flavor.ID)

		if flavor.Name == name {
			foundFlavor = flavor
			return
		}
	}

	err = fmt.Errorf("Could not find flavor named %s", name)
	return
}

func findImage(ctx context.Context, cloudName string, name string) (foundImage images.Image, err error) {
	var (
		pager      pagination.Page
		allImages  []images.Image
		image      images.Image
	)

	connImage, err := NewServiceClient(ctx, "image", DefaultClientOpts(cloudName))
	if err != nil {
		return
	}
	fmt.Printf("findImage: connImage = %+v\n", connImage)

	pager, err = images.List(connImage, images.ListOpts{}).AllPages(ctx)
	if err != nil {
		return
	}
//	log.Debugf("findImage: pager = %+v", pager)

	allImages, err = images.ExtractImages(pager)
	if err != nil {
		return
	}
//	log.Debugf("findImage: allImages = %+v", allImages)

	for _, image = range allImages {
		log.Debugf("findImage: image.Name = %s, image.ID = %s", image.Name, image.ID)

		if image.Name == name {
			foundImage = image
			return
		}
	}

	err = fmt.Errorf("Could not find image named %s", name)
	return
}

func findNetwork(ctx context.Context, cloudName string, name string) (foundNetwork networks.Network, err error) {
	var (
		pager      pagination.Page
		allNetworks  []networks.Network
		network      networks.Network
	)

	connNetwork, err := NewServiceClient(ctx, "network", DefaultClientOpts(cloudName))
	if err != nil {
		return
	}
	fmt.Printf("findNetwork: connNetwork = %+v\n", connNetwork)

	pager, err = networks.List(connNetwork, networks.ListOpts{}).AllPages(ctx)
	if err != nil {
		return
	}
//	log.Debugf("findNetwork: pager = %+v", pager)

	allNetworks, err = networks.ExtractNetworks(pager)
	if err != nil {
		return
	}
//	log.Debugf("findNetwork: allNetworks = %+v", allNetworks)

	for _, network = range allNetworks {
		log.Debugf("findNetwork: network.Name = %s, network.ID = %s", network.Name, network.ID)

		if network.Name == name {
			foundNetwork = network
			return
		}
	}

	err = fmt.Errorf("Could not find network named %s", name)
	return
}

func findServer(ctx context.Context, cloudName string, name string) (foundServer servers.Server, err error) {
	var (
		pager      pagination.Page
		allServers []servers.Server
		server     servers.Server
	)

	connServer, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloudName))
	if err != nil {
		err = fmt.Errorf("NewServiceClient returns %v", err)
		return
	}
	log.Debugf("findServer: connServer = %+v\n", connServer)

	pager, err = servers.List(connServer, servers.ListOpts{}).AllPages(ctx)
	if err != nil {
		return
	}
//	log.Debugf("findServer: pager = %+v", pager)

	allServers, err = servers.ExtractServers(pager)
	if err != nil {
		return
	}
//	log.Debugf("findServer: allServers = %+v", allServers)

	for _, server = range allServers {
		log.Debugf("findServer: server.Name = %s, server.ID = %s", server.Name, server.ID)

		if server.Name == name {
			foundServer = server
			return
		}
	}

	err = fmt.Errorf("Could not find server named %s", name)
	return
}

func waitForServer(ctx context.Context, cloudName string, name string) error {
	var (
		err error
	)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32,
	}

	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			foundServer servers.Server
			err2        error
		)

		// Check
		foundServer, err2 = findServer(ctx, cloudName, name)
		if err2 != nil {
			log.Debugf("waitForServer: findServer returned %v", err2)

			if strings.HasPrefix(err2.Error(), "Could not find server named") {
				return false, nil
			}

			return false, err2
		}

		log.Debugf("waitForServer: foundServer.Status = %s, foundServer.PowerState = %d", foundServer.Status, foundServer.PowerState)
		if foundServer.Status == "ACTIVE" && foundServer.PowerState == servers.RUNNING {
			log.Debugf("waitForServer: found server")
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return err
	}

	return nil
}

func findKeyPair(ctx context.Context, cloudName string, name string) (foundKeyPair keypairs.KeyPair, err error) {
	var (
		pager       pagination.Page
		allKeyPairs []keypairs.KeyPair
		keypair     keypairs.KeyPair
	)

	connServer, err := NewServiceClient(ctx, "compute", DefaultClientOpts(cloudName))
	if err != nil {
		return
	}
	fmt.Printf("findKeyPair: connServer = %+v\n", connServer)

	pager, err = keypairs.List(connServer, keypairs.ListOpts{}).AllPages(ctx)
	if err != nil {
		return
	}
//	log.Debugf("findKeyPair: pager = %+v", pager)

	allKeyPairs, err = keypairs.ExtractKeyPairs(pager)
	if err != nil {
		return
	}
//	log.Debugf("findKeyPair: allKeyPairs = %+v", allKeyPairs)

	for _, keypair = range allKeyPairs {
		log.Debugf("findKeyPair: keypair.Name = %s", keypair.Name)

		if keypair.Name == name {
			foundKeyPair = keypair
			return
		}
	}

	err = fmt.Errorf("Could not find keypair named %s", name)
	return
}

func dnsForServer(ctx context.Context, cloudName string, apiKey string, bastionName string, domainName string) error {
	var (
		server       servers.Server
		ipAddress    string
		cisServiceID string
		crnstr       string
		zoneID       string
		dnsService   *dnsrecordsv1.DnsRecordsV1
		err          error
	)

	server, err = findServer(ctx, cloudName, bastionName)
	if err != nil {
		return err
	}
//	log.Debugf("server = %+v", server)

	_, ipAddress, err = findIpAddress(server)
	if err != nil {
		return err
	}
	if ipAddress == "" {
		return fmt.Errorf("ip address is empty for server %s", server.Name)
	}

	cisServiceID, _, err = getServiceInfo(ctx, apiKey, "internet-svcs", "")
	if err != nil {
		log.Errorf("getServiceInfo returns %v", err)
		return err
	}
	log.Debugf("dnsForServer: cisServiceID = %s", cisServiceID)

	crnstr, zoneID, err = getDomainCrn(ctx, apiKey, cisServiceID, domainName)
	log.Debugf("dnsForServer: crnstr = %s, zoneID = %s, err = %+v", crnstr, zoneID, err)
	if err != nil {
		log.Errorf("getDomainCrn returns %v", err)
		return err
	}

	dnsService, err = loadDnsServiceAPI(apiKey, crnstr, zoneID)
	if err != nil {
		return err
	}
	log.Debugf("dnsForServer: dnsService = %+v", dnsService)

	err = createOrDeletePublicDNSRecord(ctx,
		dnsrecordsv1.CreateDnsRecordOptions_Type_A,
		fmt.Sprintf("api.%s.%s", bastionName, domainName),
		ipAddress,
		true,
		dnsService)
	err = createOrDeletePublicDNSRecord(ctx,
		dnsrecordsv1.CreateDnsRecordOptions_Type_A,
		fmt.Sprintf("api-int.%s.%s", bastionName, domainName),
		ipAddress,
		true,
		dnsService)
	err = createOrDeletePublicDNSRecord(ctx,
		dnsrecordsv1.CreateDnsRecordOptions_Type_Cname,
		fmt.Sprintf("*.apps.%s.%s", bastionName, domainName),
		fmt.Sprintf("api.%s.%s", bastionName, domainName),
		true,
		dnsService)

	return nil
}

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}
