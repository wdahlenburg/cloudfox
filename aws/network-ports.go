package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BishopFox/cloudfox/console"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

var (
	TCP_4_SCAN string = "sudo nmap -sV"
	UDP_4_SCAN string = "sudo nmap -sU -sV"
	TCP_6_SCAN string = "sudo nmap -6 -sV"
	UDP_6_SCAN string = "sudo nmap -6 -sU -sV"
)

type NetworkPortsModule struct {
	// General configuration data
	EC2Client *ec2.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string
	Verbosity    int

	// Main module data
	IPv4           []NetworkService
	IPv6           []NetworkService
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type NetworkServices struct {
	IPv4 []NetworkService
	IPv6 []NetworkService
}

type NetworkService struct {
	AWSService string
	Region     string
	Hosts      []string
	Ports      []string
	Protocol   string
}

type NetworkAcl struct {
	ID      string
	VpcId   string
	Subnets []string
	head    *Node
	tail    *Node
}

type NaclRule struct {
	RuleNumber int32
	Protocol   string
	Cidr       string
	PortRange  []int32
	Action     bool
}

type SecurityGroup struct {
	ID    string
	VpcId string
	Rules []SecurityGroupRule
}

type SecurityGroupRule struct {
	Protocol string
	Cidr     []string
	Ports    []int32
}

var naclToSG = map[string]string{
	"-1": "-1",
	"6":  "tcp",
	"17": "udp",
}

func (m *NetworkPortsModule) PrintNetworkPorts(outputFormat string, outputDirectory string) {
	// These stuct values are used by the output module
	m.output.Verbosity = m.Verbosity
	m.output.Directory = outputDirectory
	m.output.CallingModule = "network-ports"
	m.modLog = utils.TxtLog.WithFields(logrus.Fields{
		"module": m.output.CallingModule,
	})
	if m.AWSProfile == "" {
		m.AWSProfile = utils.BuildAWSPath(m.Caller)
	}

	fmt.Printf("[%s][%s] Enumerating shared resources for account %s.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), aws.ToString(m.Caller.Account))

	wg := new(sync.WaitGroup)

	// Create a channel to signal the spinner aka task status goroutine to finish
	spinnerDone := make(chan bool)
	//fire up the the task status spinner/updated
	go console.SpinUntil(m.output.CallingModule, &m.CommandCounter, spinnerDone, "regions")

	//create a channel to receive the objects
	dataReceiver := make(chan NetworkServices)

	// Create a channel to signal to stop
	receiverDone := make(chan bool)
	go m.Receiver(dataReceiver, receiverDone)

	for _, region := range m.AWSRegions {
		wg.Add(1)
		m.CommandCounter.Pending++
		go m.executeChecks(region, wg, dataReceiver)

	}

	wg.Wait()
	// Send a message to the spinner goroutine to close the channel and stop
	spinnerDone <- true
	<-spinnerDone
	// Send a message to the data receiver goroutine to close the channel and stop
	receiverDone <- true
	<-receiverDone

	// add - if struct is not empty do this. otherwise, dont write anything.
	m.output.Headers = []string{
		"Service",
		"Region",
		"Protocol",
		"IP",
		"Ports",
	}

	// Table rows
	for _, i := range m.IPv4 {
		for _, h := range i.Hosts {
			m.output.Body = append(
				m.output.Body,
				[]string{
					i.AWSService,
					i.Region,
					i.Protocol,
					h,
					strings.Join(i.Ports, ","),
				},
			)
		}
	}

	for _, i := range m.IPv6 {
		for _, h := range i.Hosts {
			m.output.Body = append(
				m.output.Body,
				[]string{
					i.AWSService,
					i.Region,
					i.Protocol,
					h,
					strings.Join(i.Ports, ","),
				},
			)
		}
	}

	if len(m.IPv4) > 0 || len(m.IPv6) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(m.Verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		m.writeLoot(m.output.FilePath)
		fmt.Printf("[%s][%s] %s network services found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))

	} else {
		fmt.Printf("[%s][%s] No network services found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}
}

func (m *NetworkPortsModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan NetworkServices) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getEC2NetworkPortsPerRegion(r, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}

func (m *NetworkPortsModule) Receiver(receiver chan NetworkServices, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			if len(data.IPv4) != 0 {
				m.IPv4 = append(m.IPv4, data.IPv4...)
			}
			if len(data.IPv6) != 0 {
				m.IPv6 = append(m.IPv6, data.IPv6...)
			}
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *NetworkPortsModule) writeLoot(outputDirectory string) {
	path := filepath.Join(outputDirectory, "loot")
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		m.modLog.Error(err.Error())
	}

	if len(m.IPv4) > 0 {
		ipv4Filename := filepath.Join(path, "network-ports-ipv4.txt")

		var out string
		out = fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("# The network services may have various ingress rules depending on your source IP.")
		out = out + fmt.Sprintln("# Try scanning from any or all network locations, such as within a VPC.")
		out = out + fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("")

		for _, ipv4 := range m.IPv4 {
			if ipv4.Protocol == "tcp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", TCP_4_SCAN, strings.Join(ipv4.Ports, ","), strings.Join(ipv4.Hosts, " "))
			}

			if ipv4.Protocol == "udp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", UDP_4_SCAN, strings.Join(ipv4.Ports, ","), strings.Join(ipv4.Hosts, " "))
			}
		}

		err = os.WriteFile(ipv4Filename, []byte(out), 0644)
		if err != nil {
			m.modLog.Error(err.Error())
		}

		if m.Verbosity > 2 {
			fmt.Println()
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to manually inspect certain buckets of interest."))
			fmt.Print(out)
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
		}

		fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), ipv4Filename)
	}

	if len(m.IPv6) > 0 {
		ipv6Filename := filepath.Join(path, "network-ports-ipv6.txt")

		var out string
		out = fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("# The network services may have various ingress rules depending on your source IP.")
		out = out + fmt.Sprintln("# Try scanning from any or all network locations, such as within a VPC.")
		out = out + fmt.Sprintln("# Make sure the host you scan IPv6 from has an IPv6 network interface.")
		out = out + fmt.Sprintln("#############################################")
		out = out + fmt.Sprintln("")

		for _, ipv6 := range m.IPv6 {

			if ipv6.Protocol == "tcp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", TCP_6_SCAN, strings.Join(ipv6.Ports, ","), strings.Join(ipv6.Hosts, " "))
			}

			if ipv6.Protocol == "udp" {
				out = out + fmt.Sprintf("%s -p %s %s\n", UDP_6_SCAN, strings.Join(ipv6.Ports, ","), strings.Join(ipv6.Hosts, " "))
			}
		}

		err = os.WriteFile(ipv6Filename, []byte(out), 0644)
		if err != nil {
			m.modLog.Error(err.Error())
		}

		if m.Verbosity > 2 {
			fmt.Println()
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("Use the commands below to manually inspect certain buckets of interest."))
			fmt.Print(out)
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), green("End of loot file."))
		}

		fmt.Printf("[%s][%s] Loot written to [%s]\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), ipv6Filename)
	}

}

func (m *NetworkPortsModule) getEC2NetworkPortsPerRegion(r string, dataReceiver chan NetworkServices) {
	securityGroups := m.getEC2SecurityGroups(r)
	nacls := m.getEC2NACLs(r)

	for _, instance := range m.getEC2Instances(r) {
		var ipv4, ipv6 []string
		for _, nic := range instance.NetworkInterfaces {
			// ipv4
			for _, addr := range nic.PrivateIpAddresses {
				if addr.Association != nil {
					if addr.Association.PublicIp != nil {
						ipv4 = addHost(ipv4, aws.ToString(addr.Association.PublicIp))
					}
				}

				if addr.PrivateIpAddress != nil {
					ipv4 = addHost(ipv4, aws.ToString(addr.PrivateIpAddress))
				}
			}

			for _, addr := range nic.Ipv6Addresses {
				if addr.Ipv6Address != nil {
					ipv6 = addHost(ipv6, aws.ToString(addr.Ipv6Address))
				}
			}
		}
		var groups []SecurityGroup
		// Loop through the NICs as not all NIC SGs are added to instance.SecurityGroups
		for _, nic := range instance.NetworkInterfaces {
			for _, group := range nic.Groups {
				for _, g := range securityGroups {
					if aws.ToString(group.GroupId) == aws.ToString(g.GroupId) {
						groups = append(groups, m.parseSecurityGroup(g))
					}
				}
			}
		}
		var networkAcls []NetworkAcl
		for _, nacl := range nacls {
			for _, assoc := range nacl.Associations {
				if aws.ToString(instance.SubnetId) == aws.ToString(assoc.SubnetId) {
					networkAcls = append(networkAcls, m.parseNacl(nacl))
				}
			}
		}

		tcpPorts, udpPorts := m.resolveNetworkAccess(groups, networkAcls)

		if m.Verbosity > 0 {
			fmt.Printf("[%s][%s] %s \n", cyan(m.output.CallingModule), cyan(m.AWSProfile), fmt.Sprintf("Instance: %s, TCP Ports: %v, UDP Ports: %v", aws.ToString(instance.InstanceId), tcpPorts, udpPorts))
		}

		var networkServices NetworkServices

		// IPV4
		if len(ipv4) > 0 {

			if len(tcpPorts) > 0 {
				networkServices.IPv4 = append(networkServices.IPv4, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4, Ports: tcpPorts, Protocol: "tcp"})
			}
			if len(udpPorts) > 0 {
				networkServices.IPv4 = append(networkServices.IPv4, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv4, Ports: udpPorts, Protocol: "udp"})
			}
		}

		// IPV6
		if len(ipv6) > 0 {
			if len(tcpPorts) > 0 {
				networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv6, Ports: tcpPorts, Protocol: "tcp"})
			}
			if len(udpPorts) > 0 {
				networkServices.IPv6 = append(networkServices.IPv6, NetworkService{AWSService: "EC2", Region: r, Hosts: ipv6, Ports: udpPorts, Protocol: "udp"})
			}
		}
		dataReceiver <- networkServices
	}
}

func (m *NetworkPortsModule) getEC2SecurityGroups(region string) []types.SecurityGroup {
	var securityGroups []types.SecurityGroup
	var PaginationControl *string

	for {
		DescribeSecurityGroups, err := m.EC2Client.DescribeSecurityGroups(
			context.TODO(),
			&(ec2.DescribeSecurityGroupsInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		securityGroups = append(securityGroups, DescribeSecurityGroups.SecurityGroups...)

		if DescribeSecurityGroups.NextToken != nil {
			PaginationControl = DescribeSecurityGroups.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return securityGroups
}

func (m *NetworkPortsModule) parseSecurityGroup(group types.SecurityGroup) SecurityGroup {
	id := aws.ToString(group.GroupId)
	vpcId := aws.ToString(group.VpcId)
	var rules []SecurityGroupRule
	for _, entry := range group.IpPermissions {
		protocol := aws.ToString(entry.IpProtocol)
		var cidrs []string
		for _, i := range entry.IpRanges {
			cidrs = append(cidrs, aws.ToString(i.CidrIp))
		}
		var ports []int32
		if aws.ToInt32(entry.FromPort) == int32(0) && aws.ToInt32(entry.ToPort) == int32(0) {
			ports = generateRange(0, 65535)
		} else {
			ports = generateRange(aws.ToInt32(entry.FromPort), aws.ToInt32(entry.ToPort))
		}
		rules = append(rules, SecurityGroupRule{
			Protocol: protocol,
			Cidr:     cidrs,
			Ports:    ports,
		})
	}

	return SecurityGroup{
		ID:    id,
		VpcId: vpcId,
		Rules: rules,
	}
}

// func printSecurityGroup(group types.SecurityGroup) {
// 	fmt.Printf("ID: %s\n", aws.ToString(group.GroupId))
// 	fmt.Printf("Vpc ID: %s\n", aws.ToString(group.VpcId))
// 	for _, entry := range group.IpPermissions {
// 		fmt.Printf("\tProtocol: %s\n", aws.ToString(entry.IpProtocol))
// 		var ips []string
// 		for _, i := range entry.IpRanges {
// 			ips = append(ips, aws.ToString(i.CidrIp))
// 		}
// 		fmt.Printf("\tIP Ranges: %v\n", ips)
// 		if aws.ToInt32(entry.FromPort) == int32(0) && aws.ToInt32(entry.ToPort) == int32(0) {
// 			fmt.Printf("\tPortRange: %d - %d\n", 0, 65535)
// 		} else {
// 			fmt.Printf("\tPortRange: %d - %d\n", aws.ToInt32(entry.FromPort), aws.ToInt32(entry.ToPort))
// 		}
// 	}
// }

func (m *NetworkPortsModule) getEC2NACLs(region string) []types.NetworkAcl {
	var nacls []types.NetworkAcl
	var PaginationControl *string

	for {
		DescribeNetworkAcls, err := m.EC2Client.DescribeNetworkAcls(
			context.TODO(),
			&(ec2.DescribeNetworkAclsInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		nacls = append(nacls, DescribeNetworkAcls.NetworkAcls...)

		if DescribeNetworkAcls.NextToken != nil {
			PaginationControl = DescribeNetworkAcls.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}

	return nacls
}

func (m *NetworkPortsModule) parseNacl(nacl types.NetworkAcl) NetworkAcl {
	id := aws.ToString(nacl.NetworkAclId)
	vpcId := aws.ToString(nacl.VpcId)
	var subnets []string
	for _, assoc := range nacl.Associations {
		subnets = append(subnets, aws.ToString(assoc.SubnetId))
	}

	var rules []NaclRule
	for _, entry := range nacl.Entries {
		if aws.ToBool(entry.Egress) == false {
			ruleNumber := aws.ToInt32(entry.RuleNumber)
			protocol := aws.ToString(entry.Protocol)
			cidr := aws.ToString(entry.CidrBlock)
			var portRange []int32
			if entry.PortRange == nil {
				portRange = generateRange(0, 65535)
			} else {
				portRange = generateRange(aws.ToInt32((*entry.PortRange).From), aws.ToInt32((*entry.PortRange).To))
			}
			action := (entry.RuleAction == "allow")
			rules = append(rules, NaclRule{
				RuleNumber: ruleNumber,
				Protocol:   protocol,
				Cidr:       cidr,
				PortRange:  portRange,
				Action:     action,
			})
		}
	}

	// Sort descending
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].RuleNumber > rules[j].RuleNumber
	})

	naclList := NetworkAcl{
		ID:      id,
		VpcId:   vpcId,
		Subnets: subnets,
	}

	// Iterate over rules and create linked list
	for _, rule := range rules {
		naclList.Insert(rule)
	}

	return naclList
}

// func printNacl(nacl types.NetworkAcl) {
// 	fmt.Printf("ID: %s\n", aws.ToString(nacl.NetworkAclId))
// 	fmt.Printf("Vpc ID: %s\n", aws.ToString(nacl.VpcId))
// 	var subnets []string
// 	for _, assoc := range nacl.Associations {
// 		subnets = append(subnets, aws.ToString(assoc.SubnetId))
// 	}
// 	fmt.Printf("Associations: %v\n", subnets)
// 	for _, entry := range nacl.Entries {
// 		fmt.Printf("\tRuleNumber: %d\n", aws.ToInt32(entry.RuleNumber))
// 		fmt.Printf("\tProtocol: %s\n", aws.ToString(entry.Protocol))
// 		fmt.Printf("\tCIDR: %s\n", aws.ToString(entry.CidrBlock))
// 		fmt.Printf("\tEgress: %t\n", aws.ToBool(entry.Egress))
// 		if entry.PortRange == nil {
// 			fmt.Printf("\tPortRange: all\n")
// 		} else {
// 			var ports types.PortRange = *entry.PortRange
// 			fmt.Printf("\tPortRange: %d - %d\n", aws.ToInt32(ports.From), aws.ToInt32(ports.To))
// 		}
// 		fmt.Printf("\tRuleAction: %s\n", entry.RuleAction)
// 	}
// }

func (m *NetworkPortsModule) getEC2Instances(region string) []types.Instance {
	var instances []types.Instance
	var PaginationControl *string
	for {

		DescribeInstances, err := m.EC2Client.DescribeInstances(
			context.TODO(),
			&(ec2.DescribeInstancesInput{
				NextToken: PaginationControl,
			}),
			func(o *ec2.Options) {
				o.Region = region
			},
		)
		if err != nil {
			m.modLog.Error(err.Error())
			m.CommandCounter.Error++
			break
		}

		for _, reservation := range DescribeInstances.Reservations {

			for _, instance := range reservation.Instances {
				instances = append(instances, instance)
			}
		}

		if DescribeInstances.NextToken != nil {
			PaginationControl = DescribeInstances.NextToken
		} else {
			PaginationControl = nil
			break
		}
	}
	return instances
}

func (m *NetworkPortsModule) resolveNetworkAccess(groups []SecurityGroup, nacls []NetworkAcl) ([]string, []string) {
	/*
		// Loop through each security group
			// Loop through the rules for the security group
				// Check if the rules are explicitly allowed by a NACL
				// If not, is there a default deny?

				// Print out allowed mapping

	*/

	var udpPorts []int32
	var tcpPorts []int32

	for _, group := range groups {
		for _, rule := range group.Rules {
			for _, nacl := range nacls {
				for _, port := range rule.Ports {
					res, naclRule := nacl.Evaluate(port, rule.Protocol)
					if res && (naclToSG[naclRule.Protocol] == rule.Protocol || naclToSG[naclRule.Protocol] == "-1") {
						if rule.Protocol == "-1" && naclToSG[naclRule.Protocol] == rule.Protocol {
							tcpPorts = addPort(tcpPorts, port)
							udpPorts = addPort(udpPorts, port)
						} else if rule.Protocol == "tcp" {
							tcpPorts = addPort(tcpPorts, port)
						} else if rule.Protocol == "udp" {
							udpPorts = addPort(udpPorts, port)
						}
					}
				}
			}
		}
	}

	sort.Slice(tcpPorts, func(i, j int) bool {
		return tcpPorts[i] < tcpPorts[j]
	})

	sort.Slice(udpPorts, func(i, j int) bool {
		return udpPorts[i] < udpPorts[j]
	})

	return prettyPorts(tcpPorts), prettyPorts(udpPorts)
}

func generateRange(start int32, end int32) []int32 {
	arr := make([]int32, end-start+1)
	for i := int32(0); int(i) < len(arr); i++ {
		arr[i] = i + start
	}
	return arr
}

func contains(arr []int32, v int32) bool {
	// Quick eval for all-ports
	if len(arr) == 65536 && arr[0] == int32(0) && arr[len(arr)-1] == int32(65535) {
		return true
	}
	for _, a := range arr {
		if a == v {
			return true
		}
	}

	return false
}

func strContains(arr []string, v string) bool {
	for _, a := range arr {
		if a == v {
			return true
		}
	}
	return false
}

func addPort(arr []int32, v int32) []int32 {
	if !contains(arr, v) {
		arr = append(arr, v)
	}
	return arr
}

func addHost(arr []string, v string) []string {
	if !strContains(arr, v) {
		arr = append(arr, v)
	}
	return arr
}

type Node struct {
	prev *Node
	next *Node
	rule NaclRule
}

func (L *NetworkAcl) Insert(rule NaclRule) {
	list := &Node{
		next: L.head,
		rule: rule,
	}
	if L.head != nil {
		L.head.prev = list
	}
	L.head = list

	l := L.head
	for l.next != nil {
		l = l.next
	}
	L.tail = l
}

func (l *NetworkAcl) Evaluate(port int32, proto string) (bool, *NaclRule) {
	node := l.head
	for node != nil {

		// fmt.Printf("Checking if %d/%s is allowed in: \n", port, proto) // node.rule)

		if contains(node.rule.PortRange, port) {
			if val, ok := naclToSG[node.rule.Protocol]; ok {
				if val == proto || val == "-1" || proto == "-1" {
					return node.rule.Action, &node.rule
				}
			} else {
				fmt.Printf("Protocol: %d not supported\n", node.rule.Protocol)
			}

		}

		node = node.next
	}

	return false, nil
}

// Assumes sorted list of input
func prettyPorts(arr []int32) []string {
	var ports []string

	var first int32 = -1
	var last int32 = -1
	for i, v := range arr {
		if i == 0 {
			first = v
		} else {
			if last == -1 {
				if first+int32(1) == v {
					last = v
				} else {
					ports = append(ports, fmt.Sprintf("%d", first))
					first = v
					last = -1
				}
			} else if last != -1 && last+int32(1) == v {
				last = v
			} else {
				ports = append(ports, fmt.Sprintf("%d-%d", first, last))

				first = v
				last = -1
			}
		}
	}

	if last != -1 {
		ports = append(ports, fmt.Sprintf("%d-%d", first, last))
	} else if first != -1 {
		ports = append(ports, fmt.Sprintf("%d", first))
	}

	return ports
}
