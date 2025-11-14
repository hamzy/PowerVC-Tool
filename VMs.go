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
	"fmt"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/hypervisors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
)

const (
	VMsName = "Virtual Machines"
)

type VMs struct {
	services *Services
}

func NewVMs(services *Services) ([]RunnableObject, []error) {
	var (
		vms  []*VMs
		errs []error
		ros  []RunnableObject
	)

	vms, errs = innerNewVMs(services)

	ros = make([]RunnableObject, len(vms))
	// Go does not support type converting the entire array.
	// So we do it manually.
	for i, v := range vms {
		ros[i] = RunnableObject(v)
	}

	return ros, errs
}

func NewVMsAlt(services *Services) ([]*VMs, []error) {
	return innerNewVMs(services)
}

func innerNewVMs(services *Services) ([]*VMs, []error) {
	var (
		vms  []*VMs
		errs []error
	)

	vms = make([]*VMs, 1)
	errs = make([]error, 1)

	vms[0] = &VMs{
		services: services,
	}

	return vms, errs
}

func (vms *VMs) Name() (string, error) {
	return VMsName, nil
}

func (vms *VMs) ObjectName() (string, error) {
	return VMsName, nil
}

func (vms *VMs) Run() error {
	// Nothing needs to be done here.
	return nil
}

func (vms *VMs) ClusterStatus() {
	var (
		ctx            context.Context
		cancel         context.CancelFunc
		connCompute    *gophercloud.ServiceClient
		infraID        string
		allServers     []servers.Server
		server         servers.Server
		allHypervisors []hypervisors.Hypervisor
		err            error
	)

	ctx, cancel = vms.services.GetContextWithTimeout()
	defer cancel()

	connCompute, err = NewServiceClient(ctx, "compute", DefaultClientOpts(vms.services.GetCloud()))
	if err != nil {
		fmt.Printf("%s: Error: NewServiceClient returns error %v\n", VMsName, err)
		return
	}

	infraID = vms.services.GetMetadata().GetInfraID()
	log.Debugf("ClusterStatus: infraID = %s", infraID)

	allServers, err = getAllServers(ctx, connCompute)
	if err != nil {
		fmt.Printf("%s: Error: getAllServers returns error %v\n", VMsName, err)
		return
	}

	allHypervisors, err = getAllHypervisors(ctx, connCompute)
	if err != nil {
		fmt.Printf("%s: Error: getAllHypervisors returns error %v\n", VMsName, err)
		return
	}

	fmt.Println("8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------")

	for _, server = range allServers {
		var (
			macAddress         string
			ipAddress          string
			sshAlive           = "DEAD"
			hypervisor         hypervisors.Hypervisor
		)

		if !strings.HasPrefix(strings.ToLower(server.Name), infraID) {
			log.Debugf("ClusterStatus: SKIPPING server = %s", server.Name)
			continue
		}
		log.Debugf("ClusterStatus: FOUND    server = %s", server.Name)

		macAddress, ipAddress, err = findIpAddress(server)
		if err != nil {
			log.Debugf("ClusterStatus: findIpAddress received error %v", err)
			continue
		}

		outb, err := keyscanServer(ctx, ipAddress, true)
		if err == nil && len(outb) != 0 {
			sshAlive = "ALIVE"
		}

		fmt.Printf("%s: %s has status (%s), power state (%s), MAC address (%s), IP address (%s), and ssh status (%s)\n",
			VMsName,
			server.Name,
			server.Status,
			server.PowerState.String(),
			macAddress,
			ipAddress,
			sshAlive,
		)
		fmt.Println()

		log.Debugf("ClusterStatus: server.HypervisorHostname = %s", server.HypervisorHostname)
		hypervisor, err = findHypervisorverInList(allHypervisors, server.HypervisorHostname)
		log.Debugf("ClusterStatus: hypervisor = %+v\n", hypervisor)
		if err != nil {
			log.Debugf("ClusterStatus: findHypervisorverInList received error %v\n", err)
			continue
		}

		if false {
			fmt.Printf("%s: Console reached via: sshpass -p ${SSH_PASSWORD} ssh -t hscroot@%s mkvterm -m %s -p %s\n",
				VMsName,
				hypervisor.HostIP,
				hypervisor.HypervisorHostname,
				server.InstanceName,
			)
			fmt.Println()
		}
	}
}

func (vms *VMs) Priority() (int, error) {
	return -1, nil
}
