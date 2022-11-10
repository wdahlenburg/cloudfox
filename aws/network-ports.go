package aws

import (
	"context"
	"fmt"
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

type NetworkPortsModule struct {
	// General configuration data
	EC2Client *ec2.Client

	Caller       sts.GetCallerIdentityOutput
	AWSRegions   []string
	OutputFormat string
	Goroutines   int
	AWSProfile   string

	// Main module data
	PortsData      []PortsData
	CommandCounter console.CommandCounter
	// Used to store output data for pretty printing
	output utils.OutputData2
	modLog *logrus.Entry
}

type PortsData struct {
	AWSService string
	Region     string
	Name       string
	Ports      []int32
}

type NetworkAcl struct {
	ID      string
	VpcId   string
	Subnets []string
	Rules   []NaclRule
}

type NaclRule struct {
	RuleNumber int32
	Protocol   string
	Cidr       string
	Egress     bool
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

func (m *NetworkPortsModule) PrintNetworkPorts(outputFormat string, outputDirectory string, verbosity int) {
	// These stuct values are used by the output module
	m.output.Verbosity = verbosity
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
	dataReceiver := make(chan PortsData)

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
		"Share Name",
		"Type",
		"Owner",
		"Share Type",
	}

	// Table rows
	for i := range m.PortsData {
		m.output.Body = append(
			m.output.Body,
			[]string{
				m.PortsData[i].AWSService,
				m.PortsData[i].Region,
				m.PortsData[i].Name,
				strings.Trim(strings.Join(strings.Fields(fmt.Sprint(m.PortsData[i].Ports)), ","), "[]"),
			},
		)

	}
	if len(m.output.Body) > 0 {
		m.output.FilePath = filepath.Join(outputDirectory, "cloudfox-output", "aws", m.AWSProfile)
		//m.output.OutputSelector(outputFormat)
		utils.OutputSelector(verbosity, outputFormat, m.output.Headers, m.output.Body, m.output.FilePath, m.output.CallingModule, m.output.CallingModule)
		fmt.Printf("[%s][%s] %s resources found.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile), strconv.Itoa(len(m.output.Body)))
	} else {
		fmt.Printf("[%s][%s] No resources found, skipping the creation of an output file.\n", cyan(m.output.CallingModule), cyan(m.AWSProfile))
	}

}

func (m *NetworkPortsModule) executeChecks(r string, wg *sync.WaitGroup, dataReceiver chan PortsData) {
	defer wg.Done()
	m.CommandCounter.Total++
	m.CommandCounter.Pending--
	m.CommandCounter.Executing++
	m.getEC2NetworkPortsPerRegion(r, dataReceiver)
	m.CommandCounter.Executing--
	m.CommandCounter.Complete++
}

func (m *NetworkPortsModule) Receiver(receiver chan PortsData, receiverDone chan bool) {
	defer close(receiverDone)
	for {
		select {
		case data := <-receiver:
			m.PortsData = append(m.PortsData, data)
		case <-receiverDone:
			receiverDone <- true
			return
		}
	}
}

func (m *NetworkPortsModule) getEC2NetworkPortsPerRegion(r string, dataReceiver chan PortsData) {
	fmt.Printf("Evaluating region: %s\n", r)
	securityGroups := m.getEC2SecurityGroups(r)
	nacls := m.getEC2NACLs(r)

	for _, instance := range m.getEC2Instances(r) {
		fmt.Printf("Instance: %s\n", aws.ToString(instance.InstanceId))
		fmt.Printf("Network interfaces: %v\n", instance.NetworkInterfaces)
		fmt.Printf("Private IP: %s\n", aws.ToString(instance.PrivateIpAddress))
		fmt.Printf("Public IP: %s\n", aws.ToString(instance.PublicIpAddress))
		fmt.Printf("Security Groups: \n")
		var groups []SecurityGroup
		// Loop through the NICs as not all NIC SGs are added to instance.SecurityGroups
		for _, nic := range instance.NetworkInterfaces {
			for _, group := range nic.Groups {
				for _, g := range securityGroups {
					if aws.ToString(group.GroupId) == aws.ToString(g.GroupId) {
						printSecurityGroup(g)
						groups = append(groups, m.parseSecurityGroup(g))
					}
				}
			}
		}
		fmt.Printf("Subnet ID: %s\n", aws.ToString(instance.SubnetId))
		var networkAcls []NetworkAcl
		for _, nacl := range nacls {
			for _, assoc := range nacl.Associations {
				if aws.ToString(instance.SubnetId) == aws.ToString(assoc.SubnetId) {
					printNacl(nacl)
					networkAcls = append(networkAcls, m.parseNacl(nacl))
				}
			}
		}
		fmt.Printf("Vpc ID: %s\n", aws.ToString(instance.VpcId))

		m.resolveNetworkAccess(groups, networkAcls)
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

	// fmt.Printf("Security groups are %v\n", securityGroups)
	for _, group := range securityGroups {
		printSecurityGroup(group)
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
		fmt.Printf("From is %d\n", aws.ToInt32(entry.FromPort))
		fmt.Printf("To is %d\n", aws.ToInt32(entry.ToPort))
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

func printSecurityGroup(group types.SecurityGroup) {
	fmt.Printf("ID: %s\n", aws.ToString(group.GroupId))
	fmt.Printf("Vpc ID: %s\n", aws.ToString(group.VpcId))
	for _, entry := range group.IpPermissions {
		fmt.Printf("\tProtocol: %s\n", aws.ToString(entry.IpProtocol))
		var ips []string
		for _, i := range entry.IpRanges {
			ips = append(ips, aws.ToString(i.CidrIp))
		}
		fmt.Printf("\tIP Ranges: %v\n", ips)
		if aws.ToInt32(entry.FromPort) == int32(0) && aws.ToInt32(entry.ToPort) == int32(0) {
			fmt.Printf("\tPortRange: %d - %d\n", 0, 65535)
		} else {
			fmt.Printf("\tPortRange: %d - %d\n", aws.ToInt32(entry.FromPort), aws.ToInt32(entry.ToPort))
		}
	}
}

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

	for _, nacl := range nacls {
		printNacl(nacl)
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
		ruleNumber := aws.ToInt32(entry.RuleNumber)
		protocol := aws.ToString(entry.Protocol)
		cidr := aws.ToString(entry.CidrBlock)
		egress := aws.ToBool(entry.Egress)
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
			Egress:     egress,
			PortRange:  portRange,
			Action:     action,
		})
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].RuleNumber < rules[j].RuleNumber
	})

	return NetworkAcl{
		ID:      id,
		VpcId:   vpcId,
		Subnets: subnets,
		Rules:   rules,
	}
}

func printNacl(nacl types.NetworkAcl) {
	fmt.Printf("ID: %s\n", aws.ToString(nacl.NetworkAclId))
	fmt.Printf("Vpc ID: %s\n", aws.ToString(nacl.VpcId))
	var subnets []string
	for _, assoc := range nacl.Associations {
		subnets = append(subnets, aws.ToString(assoc.SubnetId))
	}
	fmt.Printf("Associations: %v\n", subnets)
	for _, entry := range nacl.Entries {
		fmt.Printf("\tRuleNumber: %d\n", aws.ToInt32(entry.RuleNumber))
		fmt.Printf("\tProtocol: %s\n", aws.ToString(entry.Protocol))
		fmt.Printf("\tCIDR: %s\n", aws.ToString(entry.CidrBlock))
		fmt.Printf("\tEgress: %t\n", aws.ToBool(entry.Egress))
		if entry.PortRange == nil {
			fmt.Printf("\tPortRange: all\n")
		} else {
			var ports types.PortRange = *entry.PortRange
			fmt.Printf("\tPortRange: %d - %d\n", aws.ToInt32(ports.From), aws.ToInt32(ports.To))
		}
		fmt.Printf("\tRuleAction: %s\n", entry.RuleAction)
	}
}

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

func (m *NetworkPortsModule) resolveNetworkAccess(groups []SecurityGroup, nacls []NetworkAcl) {
	fmt.Printf("%v\n", nacls)

	// SGs allow access to ports

	// NACLs restrict or allow

	/*
		// Loop through each security group
			// Loop through the rules for the security group
				// Check if the rules are explicitly allowed by a NACL
				// If not, is there a default deny?

				// Print out allowed mapping

	*/

	for _, group := range groups {
		// var udpPorts []int32
		var tcpPorts []int32
		for _, rule := range group.Rules {
			for _, nacl := range nacls {
				for _, nrule := range nacl.Rules {
					// For port in rule, see if it is in nrule
					for _, port := range rule.Ports {
						if contains(nrule.PortRange, port) && nrule.Action {
							// Protocol check
							// TODO
							tcpPorts = append(tcpPorts, port)
						}
					}
				}
			}
		}
		fmt.Printf("Ports are %v\n", tcpPorts)
	}
}

func generateRange(start int32, end int32) []int32 {
	// DEBUG
	if start == int32(0) && end == int32(65535) {
		return []int32{0}
	}
	// DEBUG
	arr := make([]int32, end-start+1)
	for i := int32(0); int(i) < len(arr); i++ {
		arr[i] = i + start
	}
	return arr
}

func contains(arr []int32, v int32) bool {
	for _, a := range arr {
		if a == v {
			return true
		}
	}

	return false
}
