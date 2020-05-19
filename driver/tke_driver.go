package driver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rancher/kontainer-engine/drivers/options"
	"github.com/rancher/kontainer-engine/drivers/util"
	"github.com/rancher/kontainer-engine/types"
	"github.com/rancher/rke/log"
	"github.com/sirupsen/logrus"
	tccommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	tke "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tke/v20180525"
	"golang.org/x/net/context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	runningStatus  = "Running"
	successStatus  = "Created"
	failedStatus   = "CreateFailed"
	notReadyStatus = "ClusterNotReadyError"
	retries        = 5
	pollInterval   = 30
)

var (
	terminate      = "terminate"
	managedCluster = "MANAGED_CLUSTER"
)

// Driver defines the struct of tke driver
type Driver struct {
	driverCapabilities types.Capabilities
}
type state struct {
	// The id of the cluster
	ClusterID string
	// The name of the cluster
	ClusterName string
	// The description of the cluster
	ClusterDesc string
	// CIDR used to assign cluster containers and service IPs must not conflict with VPC CIDR or with other cluster CIDRs in the same VPC (*required)
	ClusterCIDR string
	// Whether to ignore the ClusterCIDR conflict error, the default is 0
	// 0: Do not ignore the conflict (and return an error); 1: Ignore the conflict (continue to create)
	IgnoreClusterCIDRConflict int64
	// The version of the cluster
	ClusterVersion string
	// Create a empty cluster
	EmptyCluster bool
	// The region of the cluster
	Region string
	// The secret id used for authentication
	SecretID string
	// The secret key used for authentication
	SecretKey string
	// cluster state
	State string
	// The project ID of the cluster
	ProjectID int64

	// The zone id of the cluster
	ZoneID string
	// The number of nodes purchased, up to 100
	GoodsNum int64
	// CPU core number
	CPU int64
	// Memory size (GB)
	Mem int64
	// System name, Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64, all nodes in the cluster use this system,
	// the extension node will also automatically use this system (*required)
	OsName string
	// See CVM Instance Configuration for details . Default: S1.SMALL1
	InstanceType string
	// The type of node, the default is PayByHour
	// another option is PayByMonth
	CvmType string
	// The annual renewal fee for the annual subscription, default to NOTIFY_AND_AUTO_RENEW
	RenewFlag string
	// Type of bandwidth
	// PayByMonth vm: PayByMonth, PayByTraffic,
	// PayByHour vm: PayByHour, PayByTraffic
	BandwidthType string
	// Public network bandwidth (Mbps), when the traffic is charged for the public network bandwidth peak
	Bandwidth int64
	// Whether to open the public network IP, 0: not open 1: open
	WanIP int64
	// Private network ID
	VpcID string
	// Subnet ID
	SubnetID string
	// Whether it is a public network gateway
	// 0: non-public network gateway
	// 1: public network gateway
	IsVpcGateway int64
	// system disk size. linux system adjustment range is 20 - 50g, step size is 1
	RootSize int64
	// System disk type. System disk type restrictions are detailed in the CVM instance configuration.
	// default value of the SSD cloud drive : CLOUD_BASIC.
	RootType string
	// Data disk size (GB)
	StorageSize int64
	// Data disk type
	StorageType string
	// Node password
	Password string
	// Key ID
	KeyID string
	// The annual subscription period of the annual subscription month, unit month. This parameter is required when cvmType is PayByMonth
	Period int64
	// Security group ID, default does not bind any security groups, please fill out the inquiry list of security groups sgId field interface returned
	SgID string
	// The cluster master occupies the IP of a VPC subnet. This parameter specifies which subnet the IP is occupied by the master.
	// This subnet must be in the same VPC as the cluster.
	MasterSubnetID string
	// Base64-encoded user script, which is executed after the k8s component is run. The user is required to guarantee the reentrant and retry logic of the script.
	// The script and its generated log file can be viewed in the /data/ccs_userscript/ path of the node.
	UserScript string

	// cluster info
	ClusterInfo types.ClusterInfo
	// The total number of worker node
	NodeCount int64

	CreateClusterRequest *tke.CreateClusterRequest
}

// NewDriver init the TKE driver
func NewDriver() types.Driver {
	logrus.Println("init new driver")
	driver := &Driver{
		driverCapabilities: types.Capabilities{
			Capabilities: make(map[int64]bool),
		},
	}

	driver.driverCapabilities.AddCapability(types.GetVersionCapability)
	driver.driverCapabilities.AddCapability(types.SetVersionCapability)
	driver.driverCapabilities.AddCapability(types.GetClusterSizeCapability)
	driver.driverCapabilities.AddCapability(types.SetClusterSizeCapability)
	return driver
}

// GetDriverCreateOptions implements driver interface
func (d *Driver) GetDriverCreateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the internal name of the cluster in Rancher",
	}
	driverFlag.Options["secret-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The secretID",
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:     types.StringType,
		Password: true,
		Usage:    "The version of the cluster",
	}
	driverFlag.Options["cluster-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of the cluster that should be displayed to the user",
	}
	driverFlag.Options["cluster-desc"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The description of the cluster",
	}
	driverFlag.Options["cluster-cidr"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The IP address range of the container pods, must not conflict with VPC CIDR",
	}
	driverFlag.Options["ignore-cluster-cidr-conflict"] = &types.Flag{
		Type:    types.BoolType,
		Usage:   "Whether to ignore the ClusterCIDR conflict error, the default is false",
		Default: &types.Default{DefaultBool: false},
	}
	driverFlag.Options["cluster-version"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "The version of the cluster",
		Default: &types.Default{DefaultString: "1.10.5"},
	}
	driverFlag.Options["region"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The region of the cluster",
	}
	driverFlag.Options["project-id"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The ID of your project to use when creating a cluster",
	}
	driverFlag.Options["zoneId"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The zone id of the CVM Instance",
	}
	driverFlag.Options["imageId"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "The image id of the cluster",
		Default: &types.Default{DefaultString: "img-pyqx34y1"},
	}
	driverFlag.Options["node-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The node count of the cluster, up to 100",
	}
	driverFlag.Options["cpu"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Cpu core number",
	}
	driverFlag.Options["mem"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Memory size (GB)",
	}
	driverFlag.Options["os-name"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "The name of the operating system , currently supports Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64",
		Default: &types.Default{DefaultString: "ubuntu16.04.1 LTSx86_64"},
	}
	driverFlag.Options["instance-type"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "See CVM Instance Configuration for details . Default: S2.MEDIUM4",
		Default: &types.Default{DefaultString: "S2.MEDIUM4"},
	}
	driverFlag.Options["cvm-type"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "The cvm type of node, default to POSTPAID_BY_HOUR",
		Default: &types.Default{DefaultString: "POSTPAID_BY_HOUR"},
	}
	driverFlag.Options["bandwidth-type"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "Type of bandwidth",
		Default: &types.Default{DefaultString: "TRAFFIC_POSTPAID_BY_HOUR"},
	}
	driverFlag.Options["bandwidth"] = &types.Flag{
		Type:    types.IntType,
		Usage:   "Public network bandwidth (Mbps), when the traffic is charged for the public network bandwidth peak",
		Default: &types.Default{DefaultInt: 10},
	}
	driverFlag.Options["wan-ip"] = &types.Flag{
		Type:    types.BoolType,
		Usage:   "the cluster master occupies the IP of a VPC subnet",
		Default: &types.Default{DefaultBool: true},
	}
	driverFlag.Options["vpc-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Private network ID, please fill out the inquiry list private network interface returned unVpcId (private network unified ID) field",
	}
	driverFlag.Options["subnet-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Subnet ID, please fill out the inquiry list of subnets interface returned unSubnetId (unified subnet ID) field",
	}
	driverFlag.Options["is-vpc-gateway"] = &types.Flag{
		Type:    types.BoolType,
		Usage:   "Whether it is a public network gateway, network gateway only in public with a public IP, and in order to work properly when under private network",
		Default: &types.Default{DefaultBool: false},
	}
	driverFlag.Options["root-size"] = &types.Flag{
		Type:    types.IntType,
		Usage:   "System disk size. Linux system adjustment range is 20 - 50G, step size is 1",
		Default: &types.Default{DefaultInt: 25},
	}
	driverFlag.Options["root-type"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "System disk type. System disk type restrictions are detailed in the CVM instance configuration",
		Default: &types.Default{DefaultString: "CLOUD_BASIC"},
	}
	driverFlag.Options["storage-size"] = &types.Flag{
		Type:    types.IntType,
		Usage:   "Data disk size (GB), the step size is 10",
		Default: &types.Default{DefaultInt: 20},
	}
	driverFlag.Options["storage-type"] = &types.Flag{
		Type:    types.StringType,
		Usage:   "Data disk type, default value of the SSD cloud drive",
		Default: &types.Default{DefaultString: "CLOUD_BASIC"},
	}
	driverFlag.Options["password"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Node password. If it is not set, it will be randomly generated and sent by the station letter",
	}
	driverFlag.Options["key-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Key id, after associating the key can be used to logging to the node",
	}
	driverFlag.Options["sg-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Security group ID, default does not bind any security groups",
	}
	return &driverFlag, nil
}

// GetDriverUpdateOptions implements driver interface
func (d *Driver) GetDriverUpdateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["secret-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The secretID of the cluster",
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:     types.StringType,
		Password: true,
		Usage:    "The secretKey of the cluster",
	}
	driverFlag.Options["node-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of nodes purchased, up to 100",
	}
	driverFlag.Options["instance-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "See CVM Instance Configuration for details . Default: S2.MEDIUM4",
	}
	driverFlag.Options["storage-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Data disk size (GB), the step size is 10",
	}
	driverFlag.Options["root-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "System disk size. Linux system adjustment range is 20 - 50G, step size is 1",
	}
	driverFlag.Options["cluster-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of the cluster that should be displayed to the user",
	}
	driverFlag.Options["cluster-desc"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The description of the cluster",
	}
	driverFlag.Options["project-id"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The ID of your project to use when creating a cluster",
	}
	driverFlag.Options["bandwidth-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Type of bandwidth, PayByTraffic or PayByHour",
	}
	driverFlag.Options["bandwidth"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Public network bandwidth (Mbps), when the traffic is charged for the public network bandwidth peak",
	}
	driverFlag.Options["wan-ip"] = &types.Flag{
		Type:  types.BoolType,
		Usage: "the cluster master occupies the IP of a VPC subnet",
	}
	driverFlag.Options["is-vpc-gateway"] = &types.Flag{
		Type:  types.BoolType,
		Usage: "Whether it is a public network gateway, network gateway only in public with a public IP, and in order to work properly when under private network",
	}
	return &driverFlag, nil
}

// getStateFromOpts gets input values from opts
func getStateFromOpts(driverOptions *types.DriverOptions, isCreate bool) (*state, error) {
	d := &state{
		ClusterInfo: types.ClusterInfo{
			Metadata: map[string]string{},
		},
	}

	runInstancesPara := &cvm.RunInstancesRequest{
		Placement: &cvm.Placement{
			Zone: tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "zone-id", "zoneId").(string)),
		},
		ImageId:            tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "image-id", "imageId").(string)),
		InstanceChargeType: tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "cvm-type", "cvmType").(string)),

		InstanceType: tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "instance-type", "instanceType").(string)),
		SystemDisk: &cvm.SystemDisk{
			DiskType: tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "root-type", "rootType").(string)),
			DiskSize: tccommon.Int64Ptr(options.GetValueFromDriverOptions(driverOptions, types.IntType, "root-size", "rootSize").(int64)),
		},
		DataDisks: []*cvm.DataDisk{
			{
				DiskType: tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "storage-type", "storageType").(string)),
				DiskSize: tccommon.Int64Ptr(options.GetValueFromDriverOptions(driverOptions, types.IntType, "storage-size", "storageSize").(int64)),
			},
		},
		VirtualPrivateCloud: &cvm.VirtualPrivateCloud{
			SubnetId:     tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "subnet-id", "subnetId").(string)),
			VpcId:        tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "vpc-id", "vpcId").(string)),
			AsVpcGateway: tccommon.BoolPtr(options.GetValueFromDriverOptions(driverOptions, types.BoolType, "is-vpc-gateway", "isVpcGateway").(bool)),
		},
		InternetAccessible: &cvm.InternetAccessible{
			InternetChargeType:      tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "bandwidth-type", "bandwidthType").(string)),
			InternetMaxBandwidthOut: tccommon.Int64Ptr(options.GetValueFromDriverOptions(driverOptions, types.IntType, "bandwidth", "bandwidth").(int64)),
			PublicIpAssigned:        tccommon.BoolPtr(options.GetValueFromDriverOptions(driverOptions, types.BoolType, "wan-ip", "wanIp").(bool)),
		},
		InstanceCount: tccommon.Int64Ptr(options.GetValueFromDriverOptions(driverOptions, types.IntType, "node-count", "nodeCount").(int64)),
		LoginSettings: &cvm.LoginSettings{
			KeyIds: []*string{
				tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "key-id", "keyId").(string)),
			},
		},
		SecurityGroupIds: []*string{
			tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "sg-id", "sgId").(string)),
		},
	}

	stringRunInstancesPara := runInstancesPara.ToJsonString()

	d.CreateClusterRequest = &tke.CreateClusterRequest{
		ClusterCIDRSettings: &tke.ClusterCIDRSettings{
			ClusterCIDR:               tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-cidr", "clusterCidr").(string)),
			IgnoreClusterCIDRConflict: tccommon.BoolPtr(options.GetValueFromDriverOptions(driverOptions, types.BoolType, "ignore-cluster-cidr-conflict", "ignoreClusterCidrConflict").(bool)),
		},
		ClusterBasicSettings: &tke.ClusterBasicSettings{
			ClusterOs:          tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "os-name", "osName").(string)),
			ClusterVersion:     tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-version", "clusterVersion").(string)),
			ClusterName:        tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-name", "clusterName").(string)),
			ClusterDescription: tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-desc", "clusterDesc").(string)),
			VpcId:              tccommon.StringPtr(options.GetValueFromDriverOptions(driverOptions, types.StringType, "vpc-id", "vpcId").(string)),
			ProjectId:          tccommon.Int64Ptr(options.GetValueFromDriverOptions(driverOptions, types.IntType, "project-id", "projectId").(int64)),
		},
		ClusterType:              &managedCluster,
		ClusterAdvancedSettings:  &tke.ClusterAdvancedSettings{},
		InstanceAdvancedSettings: &tke.InstanceAdvancedSettings{},

		RunInstancesForNode: []*tke.RunInstancesForNode{
			{
				NodeRole: tccommon.StringPtr("WORKER"),
				RunInstancesPara: []*string{
					&stringRunInstancesPara,
				},
			},
		},
	}

	d.Region = options.GetValueFromDriverOptions(driverOptions, types.StringType, "region").(string)
	d.SecretID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "secret-id", "secretId").(string)
	d.SecretKey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "secret-key", "secretKey").(string)
	d.CPU = options.GetValueFromDriverOptions(driverOptions, types.IntType, "cpu").(int64)
	d.Mem = options.GetValueFromDriverOptions(driverOptions, types.IntType, "mem").(int64)
	d.NodeCount = options.GetValueFromDriverOptions(driverOptions, types.IntType, "node-count", "nodeCount").(int64)

	return d, d.validate(isCreate)
}

func (s *state) validate(isCreate bool) error {
	runInstancesPara := &cvm.RunInstancesRequest{}
	runInstancesPara.FromJsonString(*s.CreateClusterRequest.RunInstancesForNode[0].RunInstancesPara[0])
	if isCreate {
		if *s.CreateClusterRequest.ClusterBasicSettings.ClusterName == "" {
			return fmt.Errorf("cluster name is required")
		} else if *s.CreateClusterRequest.ClusterBasicSettings.ClusterVersion == "" {
			return fmt.Errorf("cluster version is required")
		} else if s.Region == "" {
			return fmt.Errorf("cluster region is required")
		} else if *runInstancesPara.VirtualPrivateCloud.SubnetId == "" {
			return fmt.Errorf("cluster subnetID is required")
		} else if *runInstancesPara.Placement.Zone == "" {
			return fmt.Errorf("cluster zoneID is required")
		} else if *runInstancesPara.VirtualPrivateCloud.VpcId == "" {
			return fmt.Errorf("cluster vpcID is required")
		} else if *runInstancesPara.SystemDisk.DiskSize == 0 {
			return fmt.Errorf("rootSize should not be set to 0")
		} else if *runInstancesPara.DataDisks[0].DiskSize == 0 {
			return fmt.Errorf("storageSize should not be set to 0")
		} else if *s.CreateClusterRequest.ClusterCIDRSettings.ClusterCIDR == "" {
			return fmt.Errorf("cluster cidr is required")
		}
	}

	if s.SecretID == "" {
		return fmt.Errorf("secretID is required")
	} else if s.SecretKey == "" {
		return fmt.Errorf("secretKey is required")
	}
	return nil
}

func getTKEServiceClient(state *state, method string) (*tke.Client, error) {
	credential := tccommon.NewCredential(state.SecretID, state.SecretKey)
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.ReqTimeout = 20
	cpf.SignMethod = "HmacSHA1"
	cpf.HttpProfile.ReqMethod = method

	client, err := tke.NewClient(credential, state.Region, cpf)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Create implements driver create interface
func (d *Driver) Create(ctx context.Context, opts *types.DriverOptions, _ *types.ClusterInfo) (*types.ClusterInfo, error) {
	state, err := getStateFromOpts(opts, true)
	if err != nil {
		return nil, err
	}

	// init tke service client
	svc, err := getTKEServiceClient(state, "POST")
	if err != nil {
		return nil, err
	}

	req, err := d.getWrapCreateClusterRequest(state)
	if err != nil {
		return nil, err
	}

	info := &types.ClusterInfo{}
	defer storeState(info, state)

	// init tke client and make create cluster api request
	resp, err := svc.CreateCluster(req)
	if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
		return info, err
	}

	if err == nil {
		state.ClusterID = *resp.Response.ClusterId
		logrus.Debugf("Cluster %s create is called for region %s.", state.ClusterID, state.Region)
	}

	if err := waitTKECluster(ctx, svc, state); err != nil {
		return info, err
	}

	return info, nil
}

func (d *Driver) getWrapCreateClusterRequest(state *state) (*tke.CreateClusterRequest, error) {
	logrus.Info("invoking createCluster")
	request := tke.NewCreateClusterRequest()
	content, err := json.Marshal(state.CreateClusterRequest)
	if err != nil {
		return nil, err
	}
	err = request.FromJsonString(string(content))
	if err != nil {
		return nil, err
	}
	return request, nil
}

func waitTKECluster(ctx context.Context, svc *tke.Client, state *state) error {
	timeout := time.Duration(30 * time.Minute)
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	tick := TickerContext(timeoutCtx, 15*time.Second)
	defer cancel()

	// Keep trying until we're timed out or got a result or got an error
	for {
		select {
		// Got a timeout! fail with a timeout error
		case <-timeoutCtx.Done():
			return fmt.Errorf("timed out waiting cluster %s to be ready", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName)
		// Got a tick, check cluster provisioning status
		case <-tick:
			cluster, err := getCluster(svc, state)
			if err != nil && !strings.Contains(err.Error(), notReadyStatus) {
				return err
			}

			if *cluster.Response.Clusters[0].ClusterStatus == runningStatus {
				log.Infof(ctx, "cluster %v is running", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName)
				return nil
			} else if *cluster.Response.Clusters[0].ClusterStatus == failedStatus {
				return fmt.Errorf("tencent cloud failed to provision cluster")
			}
		}
	}
}

func getCluster(svc *tke.Client, state *state) (*tke.DescribeClustersResponse, error) {
	logrus.Infof("invoking getCluster")
	req, err := getWrapDescribeClusterRequest(state)
	if err != nil {
		return nil, err
	}

	resp, err := svc.DescribeClusters(req)
	if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
		return resp, fmt.Errorf("an API error has returned: %s", err)
	}

	if *resp.Response.TotalCount <= 0 {
		return nil, fmt.Errorf("cluster %s is not found", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName)
	}
	return resp, nil
}

func getWrapDescribeClusterRequest(state *state) (*tke.DescribeClustersRequest, error) {
	logrus.Info("invoking describeCluster")
	request := tke.NewDescribeClustersRequest()
	defaultLimit := int64(20)
	request.Limit = &defaultLimit
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	err = request.FromJsonString(string(content))
	if err != nil {
		return nil, err
	}
	return request, nil
}

func storeState(info *types.ClusterInfo, state *state) error {
	bytes, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if info.Metadata == nil {
		info.Metadata = map[string]string{}
	}
	info.Metadata["state"] = string(bytes)
	info.Metadata["project-id"] = string(*state.CreateClusterRequest.ClusterBasicSettings.ProjectId)
	info.Metadata["zone"] = state.Region
	return nil
}

func getState(info *types.ClusterInfo) (*state, error) {
	state := &state{}
	// ignore error
	err := json.Unmarshal([]byte(info.Metadata["state"]), &state)
	return state, err
}

// Update implements driver update interface
func (d *Driver) Update(ctx context.Context, info *types.ClusterInfo, opts *types.DriverOptions) (*types.ClusterInfo, error) {
	logrus.Info("Invoking update cluster")
	state, err := getState(info)
	if err != nil {
		return nil, err
	}

	if state.CreateClusterRequest == nil {
		state = getStateFromOld(state)
	}

	newState, err := getStateFromOpts(opts, false)
	if err != nil {
		return nil, err
	}

	svc, err := getTKEServiceClient(state, "POST")
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Updating config, clusterName: %s, clusterVersion: %s, new node: %v", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName, *state.CreateClusterRequest.ClusterBasicSettings.ClusterVersion, newState.NodeCount)

	if state.NodeCount != newState.NodeCount {
		request := tke.NewDescribeClusterInstancesRequest()
		request.ClusterId = &state.ClusterID
		resp, err := svc.DescribeClusterInstances(request)
		if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
			return nil, fmt.Errorf("an API error has returned: %s", err)
		}
		nodeCount := resp.Response.TotalCount

		if newState.NodeCount > int64(*nodeCount) {

			log.Infof(ctx, "Scaling up cluster nodes to %d", newState.NodeCount)
			req, err := getWrapAddClusterInstancesRequest(state, newState, int64(*nodeCount))
			if err != nil {
				return nil, err
			}

			_, err = svc.CreateClusterInstances(req)
			if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
				return nil, err
			}
			if err == nil {
				logrus.Infof("Add cluster instances is called for cluster %s.", state.ClusterID)
			}
			if err := waitTKECluster(ctx, svc, state); err != nil {
				return nil, err
			}
		} else if newState.NodeCount < int64(*nodeCount) {
			log.Infof(ctx, "Scaling down cluster nodes to %d", newState.NodeCount)

			req, err := removeClusterInstances(state, newState, int64(*nodeCount), resp)
			if err != nil {
				return nil, err
			}

			_, err = svc.DeleteClusterInstances(req)
			if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
				return nil, err
			}
		}
		state.NodeCount = newState.NodeCount
	}

	if *newState.CreateClusterRequest.ClusterBasicSettings.ClusterName != "" || *newState.CreateClusterRequest.ClusterBasicSettings.ClusterDescription != "" {
		log.Infof(ctx, "Updating cluster %s attributes to name: %s, desc: %s", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName, *newState.CreateClusterRequest.ClusterBasicSettings.ClusterName, *newState.CreateClusterRequest.ClusterBasicSettings.ClusterDescription)
		req, err := getWrapModifyClusterAttributesRequest(state, newState)
		if err != nil {
			return nil, err
		}

		// init the TKE client
		_, err = svc.ModifyClusterAttribute(req)
		if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
			return nil, err
		}
		if err == nil {
			logrus.Infof("Modify cluster attributes is called for cluster %s.", state.ClusterID)
		}
		if err := waitTKECluster(ctx, svc, state); err != nil {
			return nil, err
		}
		*state.CreateClusterRequest.ClusterBasicSettings.ClusterName = *newState.CreateClusterRequest.ClusterBasicSettings.ClusterName
		*state.CreateClusterRequest.ClusterBasicSettings.ClusterDescription = *newState.CreateClusterRequest.ClusterBasicSettings.ClusterDescription
	}

	if *state.CreateClusterRequest.ClusterBasicSettings.ProjectId != *newState.CreateClusterRequest.ClusterBasicSettings.ProjectId {
		log.Infof(ctx, "Updating project id to %d for cluster %s", *newState.CreateClusterRequest.ClusterBasicSettings.ProjectId, *state.CreateClusterRequest.ClusterBasicSettings.ClusterName)
		req, err := getWrapModifyProjectIDRequest(state, newState)
		if err != nil {
			return nil, err
		}

		// init the TKE client
		_, err = svc.ModifyClusterAttribute(req)
		if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
			return nil, err
		}
		if err == nil {
			logrus.Infof("Modify cluster projectId is called for cluster %s.", state.ClusterID)
		}
		if err := waitTKECluster(ctx, svc, state); err != nil {
			return nil, err
		}
		*state.CreateClusterRequest.ClusterBasicSettings.ProjectId = *newState.CreateClusterRequest.ClusterBasicSettings.ProjectId
	}
	return info, storeState(info, state)
}

func getClusterCerts(svc *tke.Client, state *state) (*tke.DescribeClusterSecurityResponse, error) {
	logrus.Info("invoking getClusterCerts")

	request := tke.NewDescribeClusterSecurityRequest()
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	err = request.FromJsonString(string(content))
	if err != nil {
		return nil, err
	}

	resp, err := svc.DescribeClusterSecurity(request)
	if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
		return resp, fmt.Errorf("an API error has returned: %s", err)
	}
	return resp, nil
}

// PostCheck implements driver postCheck interface
func (d *Driver) PostCheck(ctx context.Context, info *types.ClusterInfo) (*types.ClusterInfo, error) {
	logrus.Info("starting post-check")
	clientSet, err := getClientSet(ctx, info)
	if err != nil {
		return nil, err
	}
	failureCount := 0
	for {
		info.ServiceAccountToken, err = util.GenerateServiceAccountToken(clientSet)

		if err == nil {
			logrus.Info("service account token generated successfully")
			break
		} else {
			if failureCount < retries {
				logrus.Infof("service account token generation failed, retries left: %v", retries-failureCount)
				failureCount = failureCount + 1

				time.Sleep(pollInterval * time.Second)
			} else {
				logrus.Error("retries exceeded, failing post-check")
				return nil, err
			}
		}
	}
	logrus.Info("post-check completed successfully")
	return info, nil
}

// Remove implements driver remove interface
func (d *Driver) Remove(ctx context.Context, info *types.ClusterInfo) error {
	logrus.Info("invoking removeCluster")
	state, err := getState(info)
	if err != nil {
		return err
	}

	if state == nil || state.ClusterID == "" {
		logrus.Infof("Cluster %s clusterId doesn't exist", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName)
		return nil
	}

	svc, err := getTKEServiceClient(state, "GET")
	if err != nil {
		return err
	}

	logrus.Debugf("Removing cluster %v from region %v", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName, state.Region)

	req, err := d.getWrapRemoveClusterRequest(state)
	if err != nil {
		return err
	}

	req.InstanceDeleteMode = &terminate

	_, err = svc.DeleteCluster(req)

	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		return err
	} else if err == nil {
		logrus.Debugf("Cluster %v delete is called.", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName)
	} else {
		logrus.Debugf("Cluster %s doesn't exist", *state.CreateClusterRequest.ClusterBasicSettings.ClusterName)
	}
	return nil
}

func (d *Driver) getWrapRemoveClusterRequest(state *state) (*tke.DeleteClusterRequest, error) {
	logrus.Info("invoking get remove cluster request")
	request := tke.NewDeleteClusterRequest()
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	err = request.FromJsonString(string(content))
	if err != nil {
		return nil, err
	}
	return request, nil
}

// GetCapabilities implements driver get capabilities interface
func (d *Driver) GetCapabilities(ctx context.Context) (*types.Capabilities, error) {
	return &d.driverCapabilities, nil
}

// GetClusterSize implements driver get cluster size interface
func (d *Driver) GetClusterSize(ctx context.Context, info *types.ClusterInfo) (*types.NodeCount, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	svc, err := getTKEServiceClient(state, "GET")
	if err != nil {
		return nil, err
	}
	clusters, err := getCluster(svc, state)
	if err != nil {
		return nil, err
	}
	return &types.NodeCount{Count: int64(*clusters.Response.Clusters[0].ClusterNodeNum)}, nil
}

// GetVersion implements driver get cluster kubernetes version interface
func (d *Driver) GetVersion(ctx context.Context, info *types.ClusterInfo) (*types.KubernetesVersion, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	svc, err := getTKEServiceClient(state, "GET")
	if err != nil {
		return nil, err
	}
	resp, err := getCluster(svc, state)
	if err != nil {
		return nil, err
	}
	return &types.KubernetesVersion{Version: *resp.Response.Clusters[0].ClusterVersion}, nil
}

// operateClusterVip creates or remove the cluster vip
func operateClusterVip(ctx context.Context, svc *tke.Client, clusterID, operation string) error {
	logrus.Info("invoking operateClusterVip")

	req := tke.NewCreateClusterEndpointVipRequest()
	req.ClusterId = &clusterID

	reqStatus := tke.NewDescribeClusterEndpointVipStatusRequest()
	reqStatus.ClusterId = &clusterID

	_, err := svc.CreateClusterEndpointVip(req)

	if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
		return fmt.Errorf("an API error has returned: %s", err)
	}

	count := 0
	for {
		respStatus, err := svc.DescribeClusterEndpointVipStatus(reqStatus)

		if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
			return fmt.Errorf("an API error has returned: %s", err)
		}

		if *respStatus.Response.Status == successStatus && count >= 1 {
			return nil
		} else if *respStatus.Response.Status == failedStatus {
			return fmt.Errorf("describe cluster endpoint vip status: %s", err)
		}
		count++
		time.Sleep(time.Second * 15)
	}
}

// SetClusterSize implements driver set cluster size interface
func (d *Driver) SetClusterSize(ctx context.Context, info *types.ClusterInfo, count *types.NodeCount) error {
	logrus.Info("unimplemented")
	return nil
}

// SetVersion implements driver set cluster kubernetes version interface
func (d *Driver) SetVersion(ctx context.Context, info *types.ClusterInfo, version *types.KubernetesVersion) error {
	logrus.Info("unimplemented")
	return nil
}

// RemoveLegacyServiceAccount remove any old service accounts that the driver has created
func (d *Driver) RemoveLegacyServiceAccount(ctx context.Context, info *types.ClusterInfo) error {
	clientSet, err := getClientSet(ctx, info)
	if err != nil {
		return err
	}

	return util.DeleteLegacyServiceAccountAndRoleBinding(clientSet)
}

// getClientSet returns cluster clientSet
func getClientSet(ctx context.Context, info *types.ClusterInfo) (kubernetes.Interface, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	svc, err := getTKEServiceClient(state, "GET")
	if err != nil {
		return nil, err
	}

	if err := waitTKECluster(ctx, svc, state); err != nil {
		return nil, err
	}

	cluster, err := getCluster(svc, state)
	if err != nil {
		return nil, err
	}

	certs, err := getClusterCerts(svc, state)
	if err != nil {
		return nil, err
	}

	if *certs.Response.ClusterExternalEndpoint == "" {
		err := operateClusterVip(ctx, svc, state.ClusterID, "Create")
		if err != nil {
			return nil, err
		}

		// update cluster certs with new generated cluster vip
		certs, err = getClusterCerts(svc, state)
		if err != nil {
			return nil, err
		}
	}

	info.Version = *cluster.Response.Clusters[0].ClusterVersion
	info.Endpoint = *certs.Response.ClusterExternalEndpoint
	info.RootCaCertificate = base64.StdEncoding.EncodeToString([]byte(*certs.Response.CertificationAuthority))
	info.Username = *certs.Response.UserName
	info.Password = *certs.Response.Password
	info.NodeCount = int64(*cluster.Response.Clusters[0].ClusterNodeNum)
	info.Status = *cluster.Response.Clusters[0].ClusterStatus

	host := info.Endpoint
	if !strings.HasPrefix(host, "https://") {
		host = fmt.Sprintf("https://%s", host)
	}

	config := &rest.Config{
		Host:     host,
		Username: *certs.Response.UserName,
		Password: *certs.Response.Password,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: []byte(*certs.Response.CertificationAuthority),
		},
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %v", err)
	}
	return clientSet, nil
}

// ETCDSave will backup etcd snapshot to s3 server
func (d *Driver) ETCDSave(ctx context.Context, info *types.ClusterInfo, opts *types.DriverOptions, snapshotName string) error {
	return fmt.Errorf("ETCD backup operations are not implemented")
}

// ETCDRestore will restore etcd snapshot from s3 server
func (d *Driver) ETCDRestore(ctx context.Context, info *types.ClusterInfo, opts *types.DriverOptions, snapshotName string) error {
	return fmt.Errorf("ETCD backup operations are not implemented")
}

// GetK8SCapabilities defines TKE k8s capabilities
func (d *Driver) GetK8SCapabilities(ctx context.Context, opts *types.DriverOptions) (*types.K8SCapabilities, error) {
	capabilities := &types.K8SCapabilities{
		L4LoadBalancer: &types.LoadBalancerCapabilities{
			Enabled:              true,
			Provider:             "Tencent Cloud L4 LB",
			ProtocolsSupported:   []string{"TCP", "UDP"},
			HealthCheckSupported: true,
		},
	}

	capabilities.IngressControllers = []*types.IngressCapabilities{
		{
			IngressProvider:      "Tencent Cloud Ingress",
			CustomDefaultBackend: true,
		},
	}
	return capabilities, nil
}

func removeClusterInstances(state, newState *state, nodeCount int64, instancesResp *tke.DescribeClusterInstancesResponse) (*tke.DeleteClusterInstancesRequest, error) {
	deleteCount := nodeCount - newState.NodeCount
	logrus.Debugf("invoking removeClusterInstances, delete node count: %d", deleteCount)

	var instanceIds = make([]*string, deleteCount)
	deleteNodes := instancesResp.Response.InstanceSet[:deleteCount]
	for i, node := range deleteNodes {
		instanceIds[i] = node.InstanceId
	}

	request := tke.NewDeleteClusterInstancesRequest()
	request.ClusterId = &state.ClusterID
	request.InstanceIds = instanceIds
	request.InstanceDeleteMode = &terminate

	return request, nil
}

func getWrapAddClusterInstancesRequest(state, newState *state, nodeCount int64) (*tke.CreateClusterInstancesRequest, error) {
	logrus.Debugf("invoking get wrap request of AddClusterInstances")

	runInstancesPara := &cvm.RunInstancesRequest{}

	err := json.Unmarshal([]byte(*state.CreateClusterRequest.RunInstancesForNode[0].RunInstancesPara[0]), &runInstancesPara)

	if err != nil {
		return nil, err
	}

	newRunInstancesPara := &cvm.RunInstancesRequest{}

	err = json.Unmarshal([]byte(*newState.CreateClusterRequest.RunInstancesForNode[0].RunInstancesPara[0]), &newRunInstancesPara)

	if err != nil {
		return nil, err
	}

	*runInstancesPara.InstanceCount = newState.NodeCount - nodeCount

	if *newRunInstancesPara.InstanceType != "" {
		runInstancesPara.InstanceType = newRunInstancesPara.InstanceType
	}
	if *newRunInstancesPara.InternetAccessible.InternetChargeType != "" {
		runInstancesPara.InternetAccessible.InternetChargeType = newRunInstancesPara.InternetAccessible.InternetChargeType
	}
	if *newRunInstancesPara.InternetAccessible.InternetMaxBandwidthOut != 0 {
		runInstancesPara.InternetAccessible.InternetMaxBandwidthOut = newRunInstancesPara.InternetAccessible.InternetMaxBandwidthOut
	}
	if *newRunInstancesPara.InternetAccessible.PublicIpAssigned != *runInstancesPara.InternetAccessible.PublicIpAssigned {
		runInstancesPara.InternetAccessible.PublicIpAssigned = newRunInstancesPara.InternetAccessible.PublicIpAssigned
	}

	if *newRunInstancesPara.VirtualPrivateCloud.AsVpcGateway != *runInstancesPara.VirtualPrivateCloud.AsVpcGateway {
		runInstancesPara.VirtualPrivateCloud.AsVpcGateway = newRunInstancesPara.VirtualPrivateCloud.AsVpcGateway
	}
	if *newRunInstancesPara.DataDisks[0].DiskSize != 0 {
		runInstancesPara.DataDisks[0].DiskSize = newRunInstancesPara.DataDisks[0].DiskSize
	}
	if *newRunInstancesPara.SystemDisk.DiskSize != 0 {
		runInstancesPara.SystemDisk.DiskSize = newRunInstancesPara.SystemDisk.DiskSize
	}

	stringRunInstancesPara := runInstancesPara.ToJsonString()

	request := tke.NewCreateClusterInstancesRequest()

	request.RunInstancePara = &stringRunInstancesPara
	request.ClusterId = &state.ClusterID
	return request, nil
}

func getWrapModifyClusterAttributesRequest(state, newState *state) (*tke.ModifyClusterAttributeRequest, error) {
	logrus.Debugf("invoking get wrap request of ModifyClusterAttributes")
	if *newState.CreateClusterRequest.ClusterBasicSettings.ClusterName != "" {
		*state.CreateClusterRequest.ClusterBasicSettings.ClusterName = *newState.CreateClusterRequest.ClusterBasicSettings.ClusterName
	}
	if *newState.CreateClusterRequest.ClusterBasicSettings.ClusterDescription != "" {
		*state.CreateClusterRequest.ClusterBasicSettings.ClusterDescription = *newState.CreateClusterRequest.ClusterBasicSettings.ClusterDescription
	}

	request := tke.NewModifyClusterAttributeRequest()
	request.ClusterId = &state.ClusterID
	request.ClusterName = state.CreateClusterRequest.ClusterBasicSettings.ClusterName
	request.ClusterDesc = state.CreateClusterRequest.ClusterBasicSettings.ClusterDescription

	return request, nil
}

func getWrapModifyProjectIDRequest(state, newState *state) (*tke.ModifyClusterAttributeRequest, error) {
	logrus.Debugf("invoking get wrap request of ModifyProjectId")
	if *state.CreateClusterRequest.ClusterBasicSettings.ProjectId != *newState.CreateClusterRequest.ClusterBasicSettings.ProjectId {
		*state.CreateClusterRequest.ClusterBasicSettings.ProjectId = *newState.CreateClusterRequest.ClusterBasicSettings.ProjectId
	}

	request := tke.NewModifyClusterAttributeRequest()
	request.ClusterId = &state.ClusterID
	request.ProjectId = state.CreateClusterRequest.ClusterBasicSettings.ProjectId

	return request, nil
}

func getStateFromOld(state *state) *state {

	runInstancesPara := &cvm.RunInstancesRequest{
		Placement: &cvm.Placement{
			Zone: tccommon.StringPtr(state.ZoneID),
		},
		ImageId:            tccommon.StringPtr("img-pyqx34y1"),
		InstanceChargeType: tccommon.StringPtr(state.CvmType),

		InstanceType: tccommon.StringPtr(state.InstanceType),
		SystemDisk: &cvm.SystemDisk{
			DiskType: tccommon.StringPtr(state.RootType),
			DiskSize: tccommon.Int64Ptr(state.RootSize),
		},
		DataDisks: []*cvm.DataDisk{
			{
				DiskType: tccommon.StringPtr(state.StorageType),
				DiskSize: tccommon.Int64Ptr(state.StorageSize),
			},
		},
		VirtualPrivateCloud: &cvm.VirtualPrivateCloud{
			SubnetId:     tccommon.StringPtr(state.SubnetID),
			VpcId:        tccommon.StringPtr(state.VpcID),
			AsVpcGateway: tccommon.BoolPtr(getBoolean(state.IsVpcGateway)),
		},
		InternetAccessible: &cvm.InternetAccessible{
			InternetChargeType:      tccommon.StringPtr(state.BandwidthType),
			InternetMaxBandwidthOut: tccommon.Int64Ptr(state.Bandwidth),
			PublicIpAssigned:        tccommon.BoolPtr(getBoolean(state.WanIP)),
		},
		InstanceCount: tccommon.Int64Ptr(state.NodeCount),
		LoginSettings: &cvm.LoginSettings{
			KeyIds: []*string{
				tccommon.StringPtr(state.KeyID),
			},
		},
		SecurityGroupIds: []*string{
			tccommon.StringPtr(state.SgID),
		},
	}

	stringRunInstancesPara := runInstancesPara.ToJsonString()

	state.CreateClusterRequest = &tke.CreateClusterRequest{
		ClusterCIDRSettings: &tke.ClusterCIDRSettings{
			ClusterCIDR:               tccommon.StringPtr(state.ClusterCIDR),
			IgnoreClusterCIDRConflict: tccommon.BoolPtr(getBoolean(state.IgnoreClusterCIDRConflict)),
		},
		ClusterBasicSettings: &tke.ClusterBasicSettings{
			ClusterOs:          tccommon.StringPtr(state.OsName),
			ClusterVersion:     tccommon.StringPtr(state.ClusterVersion),
			ClusterName:        tccommon.StringPtr(state.ClusterName),
			ClusterDescription: tccommon.StringPtr(state.ClusterDesc),
			VpcId:              tccommon.StringPtr(state.VpcID),
			ProjectId:          tccommon.Int64Ptr(state.ProjectID),
		},
		ClusterType:              &managedCluster,
		ClusterAdvancedSettings:  &tke.ClusterAdvancedSettings{},
		InstanceAdvancedSettings: &tke.InstanceAdvancedSettings{},

		RunInstancesForNode: []*tke.RunInstancesForNode{
			{
				NodeRole: tccommon.StringPtr("WORKER"),
				RunInstancesPara: []*string{
					&stringRunInstancesPara,
				},
			},
		},
	}

	return state
}

func getBoolean(num int64) bool {
	if num == 1 {
		return true
	}
	return false
}
