package driver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rancher/kontainer-engine-tencentkubernetesengine-driver/tencentcloud/ccs"
	"github.com/rancher/kontainer-engine/drivers/options"
	"github.com/rancher/kontainer-engine/drivers/util"
	"github.com/rancher/kontainer-engine/types"
	"github.com/rancher/rke/log"
	"github.com/sirupsen/logrus"
	tccommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"golang.org/x/net/context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	runningStatus        = "Running"
	successStatus        = "Success"
	failedStatus         = "Failed"
	notReadyStatus       = "ClusterNotReadyError"
	processRunningStatus = "ProcessAlreadyRunning"
	retries              = 5
	pollInterval         = 30
)

// Driver defines the struct of tke driver
type Driver struct {
	driverCapabilities types.Capabilities
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
		Type:  types.BoolType,
		Usage: "Whether to ignore the ClusterCIDR conflict error, the default is 0",
	}
	driverFlag.Options["cluster-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The version of the cluster",
	}
	driverFlag.Options["empty-cluster"] = &types.Flag{
		Type:  types.BoolType,
		Usage: "Create a empty cluster",
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
		Usage: "The zone id of the cluster",
	}
	driverFlag.Options["goods-num"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of nodes purchased, up to 100",
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
		Type:  types.StringType,
		Usage: "The name of the operating system , currently supports Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64",
	}
	driverFlag.Options["instance-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "See CVM Instance Configuration for details . Default: S1.SMALL1",
	}
	driverFlag.Options["cvm-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The type of node, the default is charged by volume ",
	}
	driverFlag.Options["renew-flag"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The annual renewal fee for the annual subscription, default to NOTIFY_AND_AUTO_RENEW",
	}
	driverFlag.Options["bandwidth-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Type of bandwidth",
	}
	driverFlag.Options["bandwidth"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Public network bandwidth (Mbps), when the traffic is charged for the public network bandwidth peak",
	}
	driverFlag.Options["wan-ip"] = &types.Flag{
		Type:  types.IntType,
		Usage: "the cluster master occupies the IP of a VPC subnet",
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
		Type:  types.IntType,
		Usage: "Whether it is a public network gateway, network gateway only in public with a public IP, and in order to work properly when under private network",
	}
	driverFlag.Options["root-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "System disk size. Linux system adjustment range is 20 - 50G, step size is 1",
	}
	driverFlag.Options["root-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "System disk type. System disk type restrictions are detailed in the CVM instance configuration",
	}
	driverFlag.Options["storage-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Data disk size (GB), the step size is 10",
	}
	driverFlag.Options["storage-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Data disk type, default value of the SSD cloud drive",
	}
	driverFlag.Options["password"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Node password. If it is not set, it will be randomly generated and sent by the station letter",
	}
	driverFlag.Options["key-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Key id, after associating the key can be used to logging to the node",
	}
	driverFlag.Options["period"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The annual subscription period of the annual subscription month, unit month. This parameter is required when cvmType is PayByMonth",
	}
	driverFlag.Options["sg-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Security group ID, default does not bind any security groups",
	}
	driverFlag.Options["master-subnet-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the cluster master occupies the IP of a VPC subnet",
	}
	driverFlag.Options["user-script"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Base64-encoded user script, which is executed after the k8s component is run.",
	}
	return &driverFlag, nil
}

// GetDriverUpdateOptions implements driver interface
func (d *Driver) GetDriverUpdateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["cluster-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The ID of the existing cluster",
	}
	driverFlag.Options["cluster-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of the cluster that should be displayed to the user",
	}
	driverFlag.Options["vpc-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The private vpc id the cluster",
	}
	driverFlag.Options["cluster-desc"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The description of the cluster",
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
	return &driverFlag, nil
}

// getStateFromOpts gets input values from opts
func getStateFromOpts(driverOptions *types.DriverOptions) (*state, error) {
	d := &state{
		ClusterInfo: types.ClusterInfo{
			Metadata: map[string]string{},
		},
	}
	d.ClusterName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-name", "clusterName").(string)
	d.ClusterDesc = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-desc", "clusterDesc").(string)
	d.ClusterCIDR = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-cidr", "clusterCidr").(string)
	d.IgnoreClusterCIDRConflict = 0
	if options.GetValueFromDriverOptions(driverOptions, types.BoolType, "ingore-cluster-cidr-conflict", "ignoreClusterCidrConflict").(bool) {
		d.IgnoreClusterCIDRConflict = 1
	}
	d.ClusterVersion = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-version", "clusterVersion").(string)
	d.EmptyCluster = false
	if options.GetValueFromDriverOptions(driverOptions, types.BoolType, "empty-cluster", "emptyCluster").(bool) == true {
		d.EmptyCluster = true
	}
	d.Region = options.GetValueFromDriverOptions(driverOptions, types.StringType, "region").(string)
	d.SecretID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "secret-id", "secretId").(string)
	d.SecretKey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "secret-key", "secretKey").(string)
	d.ProjectID = options.GetValueFromDriverOptions(driverOptions, types.IntType, "project-id", "projectId").(int64)

	d.ZoneID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "zone-id", "zoneId").(string)
	d.GoodsNum = options.GetValueFromDriverOptions(driverOptions, types.IntType, "goods-num", "goodsNum").(int64)
	d.CPU = options.GetValueFromDriverOptions(driverOptions, types.IntType, "cpu").(int64)
	d.Mem = options.GetValueFromDriverOptions(driverOptions, types.IntType, "mem").(int64)
	d.OsName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "os-name", "osName").(string)
	d.InstanceType = options.GetValueFromDriverOptions(driverOptions, types.StringType, "instance-type", "instanceType").(string)
	d.CvmType = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cvm-type", "cvmType").(string)
	d.RenewFlag = options.GetValueFromDriverOptions(driverOptions, types.StringType, "renew-flag", "renewFlag").(string)
	d.BandwidthType = options.GetValueFromDriverOptions(driverOptions, types.StringType, "bandwidth-type", "bandwidthType").(string)
	d.Bandwidth = options.GetValueFromDriverOptions(driverOptions, types.IntType, "bandwidth", "bandwidth").(int64)
	d.WanIP = options.GetValueFromDriverOptions(driverOptions, types.IntType, "wan-ip", "wanIp").(int64)
	d.VpcID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "vpc-id", "vpcId").(string)
	d.SubnetID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "subnet-id", "subnetId").(string)
	d.IsVpcGateway = options.GetValueFromDriverOptions(driverOptions, types.IntType, "is-vpc-gateway", "isVpcGateway").(int64)
	d.RootSize = options.GetValueFromDriverOptions(driverOptions, types.IntType, "root-size", "rootSize").(int64)
	d.RootType = options.GetValueFromDriverOptions(driverOptions, types.StringType, "root-type", "rootType").(string)
	d.StorageSize = options.GetValueFromDriverOptions(driverOptions, types.IntType, "storage-size", "storageSize").(int64)
	d.StorageType = options.GetValueFromDriverOptions(driverOptions, types.StringType, "storage-type", "storageType").(string)
	d.Password = options.GetValueFromDriverOptions(driverOptions, types.StringType, "password").(string)
	d.KeyID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "key-id", "keyId").(string)
	d.Period = options.GetValueFromDriverOptions(driverOptions, types.IntType, "period").(int64)
	d.SgID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "sg-id", "sgId").(string)
	d.MasterSubnetID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "master-subnet-id", "masterSubnetId").(string)
	d.UserScript = options.GetValueFromDriverOptions(driverOptions, types.StringType, "user-script", "userScript").(string)

	return d, d.validate()
}

func (s *state) validate() error {
	if s.ClusterName == "" {
		return fmt.Errorf("clusterName is required")
	} else if s.ClusterCIDR == "" {
		return fmt.Errorf("clusterCidr is required")
	} else if s.SecretID == "" {
		return fmt.Errorf("secretID is required")
	} else if s.SecretKey == "" {
		return fmt.Errorf("secretKey is required")
	} else if s.Region == "" {
		return fmt.Errorf("region is required")
	}
	return nil
}

func (d *Driver) getTKEServiceClient(ctx context.Context, state *state, method string) (*ccs.Client, error) {
	credential := tccommon.NewCredential(state.SecretID, state.SecretKey)
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ccs.api.qcloud.com/v2/index.php"
	cpf.HttpProfile.ReqTimeout = 20
	cpf.SignMethod = "HmacSHA1"
	cpf.HttpProfile.ReqMethod = method

	client, err := ccs.NewClient(credential, state.Region, cpf)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Create implements driver create interface
func (d *Driver) Create(ctx context.Context, opts *types.DriverOptions, _ *types.ClusterInfo) (*types.ClusterInfo, error) {
	state, err := getStateFromOpts(opts)
	if err != nil {
		return nil, err
	}

	// init tke service client
	svc, err := d.getTKEServiceClient(ctx, state, "POST")
	if err != nil {
		return nil, err
	}

	req, err := d.getWrapCreateClusterRequest(state)
	if err != nil {
		return nil, err
	}

	// init tke client and make create cluster api request
	resp, err := svc.CreateCluster(req, state.EmptyCluster)
	if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
		return nil, err
	}

	if err == nil {
		state.ClusterID = resp.Data.ClusterID
		fmt.Printf("resp data str: %s\n", state.ClusterID)
		logrus.Debugf("Cluster %s create is called for region %s and zone %s. Status Code %v", state.ClusterID, state.Region, state.ZoneID, resp.Code)
	}

	if err := d.waitTKECluster(ctx, svc, state); err != nil {
		return nil, err
	}

	info := &types.ClusterInfo{}
	return info, storeState(info, state)
}

func (d *Driver) getWrapCreateClusterRequest(state *state) (*ccs.CreateClusterRequest, error) {
	logrus.Info("invoking createCluster")
	request := ccs.NewCreateClusterRequest(state.EmptyCluster)
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	err = request.FromJSONString(string(content))
	if err != nil {
		return nil, err
	}
	return request, nil
}

func (d *Driver) waitTKECluster(ctx context.Context, svc *ccs.Client, state *state) error {
	lastMsg := ""
	for {
		cluster, err := getCluster(svc, state)
		if err != nil && !strings.Contains(err.Error(), notReadyStatus) {
			return err
		}

		if cluster.CodeDesc != lastMsg {
			log.Infof(ctx, "provisioning cluster %s: %s", state.ClusterName, cluster.CodeDesc)
			lastMsg = cluster.CodeDesc
		}

		if cluster.Data.Clusters[0].Status == runningStatus {
			log.Infof(ctx, "cluster %v is running", state.ClusterName)
			return nil
		} else if cluster.Data.Clusters[0].Status == failedStatus {
			return fmt.Errorf("tencent cloud failed to provision cluster: %s", cluster.Message)
		}
		time.Sleep(time.Second * 15)
	}
}

func getCluster(svc *ccs.Client, state *state) (*ccs.DescribeClusterResponse, error) {
	logrus.Infof("invoking getCluster")
	req, err := getWrapDescribeClusterRequest(state)
	if err != nil {
		return nil, err
	}

	resp, err := svc.DescribeCluster(req)
	if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s\n", err)
		return resp, err
	}

	if resp.Data.TotalCount <= 0 {
		return nil, fmt.Errorf("cluster %s is not found", state.ClusterName)
	}
	return resp, nil
}

func getWrapDescribeClusterRequest(state *state) (*ccs.DescribeClusterRequest, error) {
	logrus.Info("invoking describeCluster")
	request := ccs.NewDescribeClusterRequest()
	request.Limit = 20
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	err = request.FromJSONString(string(content))
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
	info.Metadata["project-id"] = string(state.ProjectID)
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
	logrus.Info("unimplemented")
	return nil, fmt.Errorf("not implemented")
}

func getClusterCerts(svc *ccs.Client, state *state) (*ccs.DescribeClusterSecurityInfoResponse, error) {
	logrus.Infof("invoking getClusterCerts")

	request := ccs.NewDescribeClusterSecurityInfoRequest()
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	err = request.FromJSONString(string(content))
	if err != nil {
		return nil, err
	}

	resp, err := svc.DescribeClusterSecurityInfo(request)
	if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s\n", err)
		return resp, err
	}
	return resp, nil
}

// PostCheck implements driver postCheck interface
func (d *Driver) PostCheck(ctx context.Context, info *types.ClusterInfo) (*types.ClusterInfo, error) {
	logrus.Infof("Starting post-check")
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	svc, err := d.getTKEServiceClient(ctx, state, "GET")
	if err != nil {
		return nil, err
	}

	if err := d.waitTKECluster(ctx, svc, state); err != nil {
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

	if certs.Data.ClusterExternalEndpoint == "" {
		err := d.operateClusterVip(ctx, svc, state.ClusterID, "Create")
		if err != nil {
			return nil, err
		}

		// update cluster certs with new generated cluster vip
		certs, err = getClusterCerts(svc, state)
		if err != nil {
			return nil, err
		}
	}

	info.Version = cluster.Data.Clusters[0].K8sVersion
	info.Endpoint = certs.Data.ClusterExternalEndpoint
	info.RootCaCertificate = base64.StdEncoding.EncodeToString([]byte(certs.Data.CertificationAuthority))
	info.Username = certs.Data.UserName
	info.Password = certs.Data.Password
	info.NodeCount = cluster.Data.Clusters[0].NodeNum
	info.Status = cluster.Data.Clusters[0].Status

	host := info.Endpoint
	if !strings.HasPrefix(host, "https://") {
		host = fmt.Sprintf("https://%s", host)
	}

	config := &rest.Config{
		Host:     host,
		Username: certs.Data.UserName,
		Password: certs.Data.Password,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: []byte(certs.Data.CertificationAuthority),
		},
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %v", err)
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
	state, err := getState(info)
	if err != nil {
		return err
	}
	svc, err := d.getTKEServiceClient(ctx, state, "GET")
	if err != nil {
		return err
	}

	logrus.Debugf("Removing cluster %v from region %v, zone %v", state.ClusterName, state.Region, state.ZoneID)

	req, err := d.getWrapRemoveClusterRequest(state)
	if err != nil {
		return err
	}
	resp, err := svc.DeleteCluster(req)
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		return err
	} else if err == nil {
		logrus.Debugf("Cluster %v delete is called. Status Code %v", state.ClusterName, resp.Code)
	} else {
		logrus.Debugf("Cluster %s doesn't exist", state.ClusterName)
	}
	return nil
}

func (d *Driver) getWrapRemoveClusterRequest(state *state) (*ccs.DeleteClusterRequest, error) {
	logrus.Info("invoking removeCluster")
	request := ccs.NewDeleteClusterRequest()
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	err = request.FromJSONString(string(content))
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
	svc, err := d.getTKEServiceClient(ctx, state, "GET")
	if err != nil {
		return nil, err
	}
	clusters, err := getCluster(svc, state)
	if err != nil {
		return nil, err
	}
	return &types.NodeCount{Count: clusters.Data.Clusters[0].NodeNum}, nil
}

// GetVersion implements driver get cluster kubernetes version interface
func (d *Driver) GetVersion(ctx context.Context, info *types.ClusterInfo) (*types.KubernetesVersion, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	svc, err := d.getTKEServiceClient(ctx, state, "GET")
	if err != nil {
		return nil, err
	}
	resp, err := getCluster(svc, state)
	if err != nil {
		return nil, err
	}
	return &types.KubernetesVersion{Version: resp.Data.Clusters[0].K8sVersion}, nil
}

// operateClusterVip creates or remove the cluster vip
func (d *Driver) operateClusterVip(ctx context.Context, svc *ccs.Client, clusterID, operation string) error {
	logrus.Infof("invoking operateClusterVip")

	req := ccs.NewOperateClusterVipRequest()
	req.ClusterID = clusterID
	req.Operation = operation

	count := 0
	for {
		resp, err := svc.OperateClusterVip(req)

		if _, ok := err.(*tcerrors.TencentCloudSDKError); ok {
			if !strings.Contains(err.Error(), processRunningStatus) {
				return err
			}
			fmt.Printf("An API error has returned: %s\n", err)
		}

		if resp.CodeDesc == successStatus && count >= 1 {
			return nil
		}
		count++
		log.Infof(ctx, "operating cluster vip: %s", resp.CodeDesc)
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
