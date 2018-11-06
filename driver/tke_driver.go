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
	"github.com/rancher/rancher-tke-driver/tencentcloud/ccs"
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
	runningStatus  = "Success"
	failedStatus   = "Failed"
	notReadyStatus = "ClusterNotReadyError"
	processRunningStatus = "ProcessAlreadyRunning"
	retries        = 5
	pollInterval   = 30
)

// Driver defines the struct of gke driver
type Driver struct {
	driverCapabilities types.Capabilities
}

type state struct {
	// The id of the cluster
	ClusterId string
	// The name of the cluster
	ClusterName string
	// The vpc id of the cluster
	VpcId string
	// Create a empty cluster
	EmptyCluster bool
	// CIDR used to assign cluster containers and service IPs must not conflict with VPC CIDR or with other cluster CIDRs in the same VPC (*required)
	ClusterCIDR string
	// The description of the cluster
	ClusterDesc string
	// The version of the cluster
	ClusterVersion string
	// System name, Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64, all nodes in the cluster use this system,
	// the extension node will also automatically use this system (*required)
	OsName string
	// The project ID of the cluster
	ProjectId int64
	// Whether to ignore the ClusterCIDR conflict error, the default is 0
	// 0: Do not ignore the conflict (and return an error); 1: Ignore the conflict (continue to create)
	IgnoreClusterCIDRConflict int64
	// The cluster master occupies the IP of a VPC subnet. This parameter specifies which subnet the IP is occupied by the master.
	// This subnet must be in the same VPC as the cluster.
	MasterSubnetId string

	// The region of the cluster
	Region string
	// The zone id of the cluster
	ZoneId string
	// The secret id used for authentication
	SecretID string
	// The secret key used for authentication
	SecretKey string

	// cluster info
	ClusterInfo types.ClusterInfo

	// cluster state
	State string
}

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
	driverFlag.Options["cluster-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of the cluster that should be displayed to the user",
	}
	driverFlag.Options["vpc-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The private vpc id of the cluster",
	}
	driverFlag.Options["empty-cluster"] = &types.Flag{
		Type:  types.BoolType,
		Usage: "Create a empty cluster",
	}
	driverFlag.Options["cluster-cidr"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The IP address range of the container pods, must not conflict with VPC CIDR",
	}
	driverFlag.Options["cluster-desc"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The description of the cluster",
	}
	driverFlag.Options["cluster-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The version of the cluster",
	}
	driverFlag.Options["secret-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The secretID",
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The version of the cluster",
	}
	driverFlag.Options["os-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of the operating system , currently supports Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64",
	}
	driverFlag.Options["project-id"] = &types.Flag{
		Type:  types.IntType,
		Usage: "the ID of your project to use when creating a cluster",
	}
	driverFlag.Options["ignore-cluster-cidr-conflict"] = &types.Flag{
		Type:  types.BoolType,
		Usage: "Whether to ignore the ClusterCIDR conflict error, the default is 0",
	}
	driverFlag.Options["master-subnet-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The cluster master occupies the IP of a VPC subnet",
	}
	driverFlag.Options["secret-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The secret id used to identify the identity of the API caller",
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The key used to encrypt the signature string and the server-side verification signature string",
	}
	driverFlag.Options["region"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The region of the cluster",
	}
	driverFlag.Options["zoneId"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The zone id of the cluster",
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
		Usage: "the description of the cluster",
	}
	driverFlag.Options["secret-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the secretID of the cluster",
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the secretKey of the cluster",
	}
	return &driverFlag, nil
}

// SetDriverOptions implements driver interface
func getStateFromOpts(driverOptions *types.DriverOptions) (*state, error) {
	d := &state{
		ClusterInfo: types.ClusterInfo{
			Metadata: map[string]string{},
		},
	}
	d.ClusterId = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-id", "clusterId").(string)
	d.ClusterName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-name", "clusterName").(string)
	d.EmptyCluster = options.GetValueFromDriverOptions(driverOptions, types.BoolType, "empty-cluster", "emptyCluster").(bool)
	d.VpcId = options.GetValueFromDriverOptions(driverOptions, types.StringType, "vpc-id", "vpcId").(string)
	d.ClusterCIDR = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-cidr", "clusterCIDR").(string)
	d.ClusterDesc = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-desc", "clusterDesc").(string)
	d.ClusterVersion = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-version", "clusterVersion").(string)
	d.OsName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "os-name", "osName").(string)
	d.ProjectId = options.GetValueFromDriverOptions(driverOptions, types.IntType, "project-id", "projectId").(int64)
	d.IgnoreClusterCIDRConflict = 0
	if options.GetValueFromDriverOptions(driverOptions, types.BoolType, "ingore-cluster-cidr-conflict", "ignoreClusterCIDRConflict").(bool) {
		d.IgnoreClusterCIDRConflict = 1
	}
	d.MasterSubnetId = options.GetValueFromDriverOptions(driverOptions, types.StringType, "master-subnet-id", "masterSubnetId").(string)
	d.SecretID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "secret-id", "secretId").(string)
	d.SecretKey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "secret-key", "secretKey").(string)
	d.Region = options.GetValueFromDriverOptions(driverOptions, types.StringType, "region").(string)
	d.ZoneId = options.GetValueFromDriverOptions(driverOptions, types.StringType, "zone-id", "zoneId").(string)

	return d, d.validate()
}

func (s *state) validate() error {
	if s.ClusterName == "" {
		return fmt.Errorf("cluster name is required")
	} else if s.ClusterCIDR == "" {
		return fmt.Errorf("cluster ipv4 cidr is required")
	} else if s.SecretID == "" {
		return fmt.Errorf("client secretID is required")
	} else if s.SecretKey == "" {
		return fmt.Errorf("client secretKey is required")
	} else if s.Region == "" {
		return fmt.Errorf("cluster region is required")
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

// Create implements driver interface
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

	if err != nil && !strings.Contains(err.Error(), "AlreadyExist") {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	if err == nil {
		fmt.Printf("resp data str: %s\n", resp.ToJsonString())
		state.ClusterId = *resp.Data.ClusterId
		logrus.Info("Cluster %s create is called for region %s and zone %s. Status Code %v", state.ClusterId, state.Region, state.ZoneId, resp.Code)
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
	err = request.FromJsonString(string(content))
	if err != nil {
		return nil, err
	}
	return request, nil
}

func (d *Driver) waitTKECluster(ctx context.Context, svc *ccs.Client, state *state) error {
	lastMsg := ""
	for {
		cluster, err := d.getCluster(svc, state)
		if err != nil && !strings.Contains(err.Error(), notReadyStatus) {
			return err
		}

		//if cluster.CodeDesc != nil {

		if cluster.CodeDesc != lastMsg {
			log.Infof(ctx, "provisioning cluster %s:%s", state.ClusterName, cluster.CodeDesc)
			lastMsg = cluster.CodeDesc
		}


		if cluster.CodeDesc == runningStatus {
			log.Infof(ctx, "Cluster %v is running", state.ClusterName)
			return nil
		} else if cluster.CodeDesc == failedStatus {
			return fmt.Errorf("tencent cloud failed to provision cluster: %s\n", cluster.Message)
		}
		//}
		time.Sleep(time.Second * 25)
	}
}

func (d *Driver) getCluster(svc *ccs.Client, state *state) (*ccs.DescribeClusterResponse, error) {
	logrus.Infof("invoking getCluster")
	req, err := d.getWrapDescribeClusterRequest(state)
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

func (d *Driver) getWrapDescribeClusterRequest(state *state) (*ccs.DescribeClusterRequest, error) {
	logrus.Info("invoking describeCluster")
	request := ccs.NewDescribeClusterRequest()
	request.Limit = 20
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
	info.Metadata["project-id"] = string(state.ProjectId)
	info.Metadata["zone"] = state.Region
	return nil
}

func getState(info *types.ClusterInfo) (*state, error) {
	state := &state{}
	// ignore error
	err := json.Unmarshal([]byte(info.Metadata["state"]), &state)
	return state, err
}

// Update implements driver interface
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
	err = request.FromJsonString(string(content))
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

// PostCheck implements driver interface
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

	cluster, err := d.getCluster(svc, state)
	if err != nil {
		return nil, err
	}

	certs, err := getClusterCerts(svc, state)
	if err != nil {
		return nil, err
	}

	if certs.Data.ClusterExternalEndpoint == "" {
		err := d.operateClusterVip(ctx, svc, state.ClusterId, "Create")
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

// Remove implements driver interface
func (d *Driver) Remove(ctx context.Context, info *types.ClusterInfo) error {
	state, err := getState(info)
	if err != nil {
		return err
	}
	svc, err := d.getTKEServiceClient(ctx, state, "GET")
	if err != nil {
		return err
	}

	logrus.Debugf("Removing cluster %v from region %v, zone %v", state.ClusterName, state.Region, state.ZoneId)

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
	err = request.FromJsonString(string(content))
	if err != nil {
		return nil, err
	}
	return request, nil
}

func (d *Driver) GetCapabilities(ctx context.Context) (*types.Capabilities, error) {
	return &d.driverCapabilities, nil
}

func (d *Driver) GetClusterSize(ctx context.Context, info *types.ClusterInfo) (*types.NodeCount, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	svc, err := d.getTKEServiceClient(ctx, state, "GET")
	if err != nil {
		return nil, err
	}
	clusters, err := d.getCluster(svc, state)
	if err != nil {
		return nil, err
	}
	return &types.NodeCount{Count: clusters.Data.Clusters[0].NodeNum}, nil
}

func (d *Driver) GetVersion(ctx context.Context, info *types.ClusterInfo) (*types.KubernetesVersion, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	svc, err := d.getTKEServiceClient(ctx, state, "GET")
	if err != nil {
		return nil, err
	}
	resp, err := d.getCluster(svc, state)
	if err != nil {
		return nil, err
	}
	return &types.KubernetesVersion{Version: resp.Data.Clusters[0].K8sVersion}, nil
}


// operateClusterVip creates or remove the cluster vip
func (d * Driver)operateClusterVip(ctx context.Context, svc *ccs.Client, clusterId, operation string) error {
	logrus.Infof("invoking operateClusterVip")

	req := ccs.NewOperateClusterVipRequest()
	req.ClusterId = clusterId
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

		if resp.CodeDesc == runningStatus && count >= 1 {
			return nil
		}
		count++
		log.Infof(ctx, "operating cluster vip: %s", resp.CodeDesc)
		time.Sleep(time.Second * 15)
	}
}


func (d *Driver) SetClusterSize(ctx context.Context, info *types.ClusterInfo, count *types.NodeCount) error {
	logrus.Info("unimplemented")
	return nil
}

func (d *Driver) SetVersion(ctx context.Context, info *types.ClusterInfo, version *types.KubernetesVersion) error {
	logrus.Info("unimplemented")
	return nil
}
