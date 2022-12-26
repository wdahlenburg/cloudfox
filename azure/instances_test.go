package azure

import (
	"fmt"
	"log"
	"testing"

	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/utils"
)

func TestAzInstancesCommand(t *testing.T) {
	fmt.Println()
	fmt.Println("[test case] Azure Instances Command")

	// Test case parameters
	utils.MockFileSystem(true)
	subtests := []struct {
		name              string
		azTenantID        string
		azSubscriptionID  string
		azVerbosity       int
		azOutputFormat    string
		version           string
		resourcesTestFile string
		vmsTestFile       string
		nicsTestFile      string
		publicIPsTestFile string
	}{
		{
			name:              "./cloudfox azure instances --tenant TENANT_ID",
			azTenantID:        "11111111-1111-1111-1111-11111111",
			azSubscriptionID:  "",
			azVerbosity:       2,
			azOutputFormat:    "table",
			version:           "DEV",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
		},
		{
			name:              "./cloudfox azure instances --subscription SUBSCRIPTION_ID",
			azTenantID:        "",
			azSubscriptionID:  "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAA",
			azVerbosity:       2,
			azOutputFormat:    "table",
			version:           "DEV",
			resourcesTestFile: "./test-data/resources.json",
			vmsTestFile:       "./test-data/vms.json",
			nicsTestFile:      "./test-data/nics.json",
			publicIPsTestFile: "./test-data/public-ips.json",
		},
	}

	// Mocked functions to simulate Azure calls and responses
	getSubscriptions = mockedGetSubscriptions
	getResourceGroups = mockedGetResourceGroups
	getComputeVMsPerResourceGroup = mockedGetComputeVMsPerResourceGroup
	getNICdetails = mockedGetNICdetails
	getPublicIP = mockedGetPublicIP

	for _, s := range subtests {
		fmt.Println()
		fmt.Printf("[subtest] %s\n", s.name)
		globals.RESOURCES_TEST_FILE = s.resourcesTestFile
		globals.VMS_TEST_FILE = s.vmsTestFile
		globals.NICS_TEST_FILE = s.nicsTestFile
		globals.PUBLIC_IPS_TEST_FILE = s.publicIPsTestFile

		err := AzInstancesCommand(s.azTenantID, s.azSubscriptionID, s.azOutputFormat, s.version, s.azVerbosity)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}
}
