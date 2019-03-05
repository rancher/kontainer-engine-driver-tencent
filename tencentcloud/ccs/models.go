package ccs

import (
	"encoding/json"

	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
)

// CreateClusterRequest defines create cluster request parameters
type CreateClusterRequest struct {
	*tchttp.BaseRequest
	// The name of the cluster
	ClusterName string `json:"clusterName" name:"clusterName"`
	// The description of the cluster
	ClusterDesc string `json:"clusterDesc" name:"clusterDesc"`
	// CIDR used to assign cluster containers and service IPs must not conflict with VPC CIDR or with other cluster CIDRs in the same VPC (*required)
	ClusterCIDR string `json:"clusterCIDR" name:"clusterCIDR"`
	// Whether to ignore the ClusterCIDR conflict error, the default is 0
	// 0: Do not ignore the conflict (and return an error); 1: Ignore the conflict (continue to create)
	IgnoreClusterCIDRConflict int64 `json:"ignoreClusterCidrConflict" name:"ignoreClusterCidrConflict"`
	// The zone id of the cluster
	ZoneID string `json:"zoneId" name:"zoneId"`
	// The number of nodes purchased, up to 100
	GoodsNum int64 `json:"goodsNum" name:"goodsNum"`
	// CPU core number
	CPU int64 `json:"cpu" name:"cpu"`
	// Memory size (GB)
	Mem int64 `json:"mem" name:"mem"`
	// System name, Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64, all nodes in the cluster use this system,
	// the extension node will also automatically use this system (*required)
	OsName string `json:"osName" name:"osName"`
	// System name, Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64, all nodes in the cluster use this system,
	// the extension node will also automatically use this system (*required)
	InstanceType string `json:"instanceType" name:"instanceType"`
	// See CVM Instance Configuration for details . Default: S1.SMALL1
	CvmType string `json:"cvmType" name:"cvmType"`
	// The annual renewal fee for the annual subscription, default to NOTIFY_AND_AUTO_RENEW
	RenewFlag string `json:"renewFlag" name:"renewFlag"`
	// Type of bandwidth
	// PayByMonth vm: PayByMonth, PayByTraffic,
	// PayByHour vm: PayByHour, PayByTraffic
	BandwidthType string `json:"bandwidthType" name:"bandwidthType"`
	// Public network bandwidth (Mbps), when the traffic is charged for the public network bandwidth peak
	Bandwidth int64 `json:"bandwidth" name:"bandwidth"`
	// Whether to open the public network IP, 0: not open 1: open
	WanIP int64 `json:"wanIp" name:"wanIp"`
	// Private network ID
	VpcID string `json:"vpcId" name:"vpcId"`
	// Subnet ID
	SubnetID string `json:"subnetId" name:"subnetId"`
	// Whether it is a public network gateway
	// 0: non-public network gateway
	// 1: public network gateway
	IsVpcGateway int64 `json:"isVpcGateway" name:"isVpcGateway"`
	// system disk size. linux system adjustment range is 20 - 50g, step size is 1
	RootSize int64 `json:"rootSize" name:"rootSize"`
	// System disk type. System disk type restrictions are detailed in the CVM instance configuration.
	// default value of the SSD cloud drive : CLOUD_BASIC.
	RootType string `json:"rootType" name:"rootType"`
	// Data disk size (GB)
	StorageSize int64 `json:"storageSize" name:"storageSize"`
	// Data disk type
	StorageType string `json:"storageType" name:"storageType"`
	// Node password
	Password string `json:"password" name:"password"`
	// Key id
	KeyID string `json:"keyId" name:"keyId"`
	// The annual subscription period of the annual subscription month, unit month. This parameter is required when cvmType is PayByMonth
	Period int64 `json:"period" name:"period"`
	// The cluster master occupies the IP of a VPC subnet. This parameter specifies which subnet the IP is occupied by the master.
	// This subnet must be in the same VPC as the cluster.
	MasterSubnetID string `json:"masterSubnetId" name:"masterSubnetId"`
	// Security group ID, default does not bind any security groups, please fill out the inquiry list of security groups sgId field interface returned
	SgID string `json:"sgId" name:"sgId"`
	// Base64-encoded user script, which is executed after the k8s component is run. The user is required to guarantee the reentrant and retry logic of the script.
	UserScript string `json:"userScript" name:"userScript"`
	// K8S cluster version
	ClusterVersion string `json:"clusterVersion" name:"clusterVersion"`
	// Project ID
	ProjectID int64 `json:"projectId" name:"projectId"`
}

// ToJSONString defines request to json format
func (r *CreateClusterRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *CreateClusterRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// CreateClusterResponse defines create cluster response
type CreateClusterResponse struct {
	*tchttp.BaseResponse
	// Public error code. 0 means success, other values ​​indicate failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
	// Cluster data
	Data struct {
		// Request ID
		RequestID int64 `json:"requestId" name:"requestId"`
		// Cluster ID
		ClusterID string `json:"clusterId" name:"clusterId"`
	} `json:"data"`
}

// ToJSONString defines request to json format
func (r *CreateClusterResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *CreateClusterResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DescribeClusterInstancesRequest defines cluster instance request
type DescribeClusterInstancesRequest struct {
	*tchttp.BaseRequest
	//Cluster ID
	ClusterID string `json:"clusterId" name:"clusterId"`
	// Offset, default 0
	Offset string `json:"offset" name:"offset"`
	// Maximum output number, default 20
	Limit string `json:"limit" name:"limit"`
	// Namespace, default is default
	Namespace string `json:"Namespace" name:"namespace"`
	// List of instances, default is empty
	InstancesID []string `json:"instancesId" name:"instancesId"`
}

// ToJSONString defines request to json format
func (r *DescribeClusterInstancesRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DescribeClusterInstancesRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DescribeClusterInstancesResponse defines describe cluster instance response
type DescribeClusterInstancesResponse struct {
	*tchttp.BaseResponse
	// Cluster data
	Data struct {
		// Total number of cluster nodes
		TotalCount int64 `json:"totalCount" name:"totalCount"`
		// Node list, details are as follows
		Nodes []Node `json:"nodes" name:"nodes"`
	} `json:"data"`
	// Public error code. 0 means success, other values ​​indicate failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to interface
	Message string `json:"message" name:"message"`
	// Business error code. Returns Success when successful, and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines request to json format
func (r *DescribeClusterInstancesResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DescribeClusterInstancesResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// Node defines the cluster node responses
type Node struct {
	InstanceID           string            `json:"instanceId" name:"instanceId"`
	ProjectID            int64             `json:"projectId" name:"projectId"`
	InstanceName         string            `json:"instanceName" name:"instanceName"`
	InstanceType         string            `json:"instanceType" name:"instanceType"`
	KernelVersion        string            `json:"kernelVersion" name:"kernelVersion"`
	PodCidr              string            `json:"podCidr" name:"podCidr"`
	CPU                  int64             `json:"cpu" name:"cpu"`
	Mem                  int64             `json:"mem" name:"mem"`
	Gpu                  int64             `json:"gpu" name:"gpu"`
	WanIP                string            `json:"wanIp" name:"wanIp"`
	LanIP                string            `json:"lanIp" name:"lanIp"`
	OsImage              string            `json:"osImage" name:"osImage"`
	IsNormal             int64             `json:"isNormal" name:"isNormal"`
	CvmState             int64             `json:"cvmState" name:"cvmState"`
	CvmPayMode           int64             `json:"cvmPayMode" name:"cvmPayMode"`
	NetworkPayMode       int64             `json:"networkPayMode" name:"networkPayMode"`
	CreatedAt            string            `json:"createdAt" name:"createdAt"`
	InstanceCreateTime   string            `json:"instanceCreateTime" name:"instanceCreateTime"`
	InstanceDeadlineTime string            `json:"instanceDeadlineTime" name:"instanceDeadlineTime"`
	ZoneID               int64             `json:"zoneId" name:"zoneId"`
	Zone                 string            `json:"zone" name:"zone"`
	AbnormalReason       AbnormalReason    `json:"abnormalReason" name:"abnormalReason"`
	Labels               map[string]string `json:"labels" name:"labels"`
	AutoScalingGroupID   string            `json:"autoScalingGroupId" name:"autoScalingGroupId"`
	Unschedulable        bool              `json:"unschedulable" name:"unschedulable"`
	DrainStatus          string            `json:"drainStatus" name:"drainStatus"`
}

// AbnormalReason defines the abnormal reason response
type AbnormalReason struct {
	MemoryPressure     string `json:"MemoryPressure" name:"MemoryPressure"`
	OutOfDisk          string `json:"OutOfDisk" name:"OutOfDisk"`
	NetworkUnavailable string `json:"NetworkUnavailable" name:"NetworkUnavailable"`
	Unknown            string `json:"Unknown" name:"Unknown"`
}

// DeleteClusterRequest defines the delete cluster request
type DeleteClusterRequest struct {
	*tchttp.BaseRequest
	ClusterID string `json:"clusterId" name:"clusterId"`
	// Cluster node deletion mode, mainly for volume-based billing hosts, the package annual subscription host can only do the removal operation
	// RemoveOnly (removal only)
	// Return (return)
	NodeDeleteMode string `json:"nodeDeleteMode" name:"nodeDeleteMode"`
}

// ToJSONString defines request to json format
func (r *DeleteClusterRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DeleteClusterRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DeleteClusterResponse defines the delete cluster response
type DeleteClusterResponse struct {
	*tchttp.BaseResponse
	// Cluster data
	Data struct {
		// Task ID
		RequestID int64 `json:"requestId" name:"requestId"`
	} `json:"data"`
	// Public error code. 0 means success, other values ​​indicate failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines request to json format
func (r *DeleteClusterResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DeleteClusterResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DescribeClusterRequest defines the delete cluster request
type DescribeClusterRequest struct {
	*tchttp.BaseRequest
	ClusterIds  []string `json:"clusterIds" name:"clusterIds"`
	ClusterName string   `json:"clusterName" name:"clusterName"`
	Status      string   `json:"status" name:"status"`
	OrderField  string   `json:"orderField" name:"orderField"`
	OrderType   string   `json:"orderType" name:"orderType"`
	Offset      int64    `json:"offset" name:"offset"`
	Limit       int64    `json:"limit" name:"limit"`
}

// ToJSONString defines request to json format
func (r *DescribeClusterRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DescribeClusterRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DescribeClusterResponse defines the describe cluster response
type DescribeClusterResponse struct {
	*tchttp.BaseResponse
	// Cluster data
	Data struct {
		// Total number of cluster nodes
		TotalCount int64 `json:"totalCount" name:"totalCount"`
		// Cluster list, details are as follows
		Clusters []Cluster `json:"clusters" name:"clusters"`
	} `json:"data"`
	// Public error code. 0 means success, other values ​​indicate failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines request to json format
func (r *DescribeClusterResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DescribeClusterResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// Cluster defines the cluster response
type Cluster struct {
	ClusterID               string `json:"clusterId" name:"clusterId"`
	ClusterName             string `json:"clusterName" name:"clusterName"`
	Description             string `json:"description" name:"description"`
	ClusterCIDR             string `json:"clusterCIDR" name:"clusterCIDR"`
	UnVpcID                 string `json:"unVpcId" name:"unVpcId"`
	VpcID                   int64  `json:"vpcId" name:"vpcId"`
	Status                  string `json:"status" name:"status"`
	NodeNum                 int64  `json:"nodeNum" name:"nodeNum"`
	NodeStatus              string `json:"nodeStatus" name:"nodeStatus"`
	TotalCPU                int64  `json:"totalCpu" name:"totalCpu"`
	TotalMem                int64  `json:"totalMem" name:"totalMem"`
	OS                      string `json:"os" name:"os"`
	CreatedAt               int64  `json:"createdAt" name:"createdAt"`
	UpdatedAt               int64  `json:"updatedAt" name:"updatedAt"`
	RegionID                string `json:"regionId" name:"regionId"`
	Region                  string `json:"region" name:"region"`
	K8sVersion              string `json:"k8sVersion" name:"k8sVersion"`
	ClusterExternalEndpoint string `json:"clusterExternalEndpoint" name:"clusterExternalEndpoint"`
	ProjectID               int64  `json:"projectId" name:"projectId"`
}

// DescribeClusterSecurityInfoRequest defines the describeClusterSecurityInfo request
type DescribeClusterSecurityInfoRequest struct {
	*tchttp.BaseRequest
	ClusterID string `json:"clusterId" name:"clusterId"`
}

// ToJSONString defines request to json format
func (r *DescribeClusterSecurityInfoRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DescribeClusterSecurityInfoRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DescribeClusterSecurityInfoResponse defines the describeClusterSecurityInfo response
type DescribeClusterSecurityInfoResponse struct {
	*tchttp.BaseResponse
	// Cluster data
	Data struct {
		UserName                string `json:"userName" name:"userName"`
		Password                string `json:"password" name:"password"`
		CertificationAuthority  string `json:"certificationAuthority" name:"certificationAuthority"`
		ClusterExternalEndpoint string `json:"clusterExternalEndpoint" name:"clusterExternalEndpoint"`
		PgwEndpoint             string `json:"pgwEndpoint" name:"pgwEndpoint"`
		Domain                  string `json:"domain" name:"domain"`
	} `json:"data"`
	// Public error code. 0 means success, other values ​​indicate failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines request to json format
func (r *DescribeClusterSecurityInfoResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *DescribeClusterSecurityInfoResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// OperateClusterVipRequest defines the clusterVip request
type OperateClusterVipRequest struct {
	*tchttp.BaseRequest
	ClusterID string `json:"clusterId" name:"clusterId"`
	Operation string `json:"operation" name:"operation"`
}

// ToJSONString defines request to json format
func (r *OperateClusterVipRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *OperateClusterVipRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// OperateClusterVipResponse defines the clusterVip response
type OperateClusterVipResponse struct {
	*tchttp.BaseResponse
	// Cluster data
	Data struct {
		RequestID string `json:"requestId" name:"requestId"`
	} `json:"data"`
	// Public error code. 0 means success, other values ​​indicate failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines request to json format
func (r *OperateClusterVipResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *OperateClusterVipResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// AddClusterInstancesRequest defines the addClusterInstances request
type AddClusterInstancesRequest struct {
	*tchttp.BaseRequest
	// The name of the cluster
	ClusterID         string `json:"clusterId" name:"clusterId"`
	ExpandInstanceNum int64  `json:"expandInstanceNum" name:"expandInstanceNum"`

	// The description of the cluster
	ClusterDesc string `json:"clusterDesc" name:"clusterDesc"`
	// The zone id of the cluster
	ZoneID string `json:"zoneId" name:"zoneId"`
	// The number of nodes purchased, up to 100
	GoodsNum int64 `json:"goodsNum" name:"goodsNum"`
	// CPU core number
	CPU int64 `json:"cpu" name:"cpu"`
	// Memory size (GB)
	Mem int64 `json:"mem" name:"mem"`
	// System name, Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64, all nodes in the cluster use this system,
	// the extension node will also automatically use this system (*required)
	OsName string `json:"osName" name:"osName"`
	// System name, Centos7.2x86_64 or ubuntu16.04.1 LTSx86_64, all nodes in the cluster use this system,
	// the extension node will also automatically use this system (*required)
	InstanceType string `json:"instanceType" name:"instanceType"`
	// See CVM Instance Configuration for details . Default: S1.SMALL1
	CvmType string `json:"cvmType" name:"cvmType"`
	// The annual renewal fee for the annual subscription, default to NOTIFY_AND_AUTO_RENEW
	RenewFlag string `json:"renewFlag" name:"renewFlag"`
	// Type of bandwidth
	// PayByMonth vm: PayByMonth, PayByTraffic,
	// PayByHour vm: PayByHour, PayByTraffic
	BandwidthType string `json:"bandwidthType" name:"bandwidthType"`
	// Public network bandwidth (Mbps), when the traffic is charged for the public network bandwidth peak
	Bandwidth int64 `json:"bandwidth" name:"bandwidth"`
	// Whether to open the public network IP, 0: not open 1: open
	WanIP int64 `json:"wanIp" name:"wanIp"`
	// Subnet ID
	SubnetID string `json:"subnetId" name:"subnetId"`
	// Whether it is a public network gateway
	// 0: non-public network gateway
	// 1: public network gateway
	IsVpcGateway int64 `json:"isVpcGateway" name:"isVpcGateway"`
	// system disk size. linux system adjustment range is 20 - 50g, step size is 1
	RootSize int64 `json:"rootSize" name:"rootSize"`
	// System disk type. System disk type restrictions are detailed in the CVM instance configuration.
	// default value of the SSD cloud drive : CLOUD_BASIC.
	RootType string `json:"rootType" name:"rootType"`
	// Data disk size (GB)
	StorageSize int64 `json:"storageSize" name:"storageSize"`
	// Data disk type
	StorageType string `json:"storageType" name:"storageType"`
	// Node password
	Password string `json:"password" name:"password"`
	// Key id
	KeyID string `json:"keyId" name:"keyId"`
	// The annual subscription period of the annual subscription month, unit month. This parameter is required when cvmType is PayByMonth
	Period int64 `json:"period" name:"period"`
	// Security group ID, default does not bind any security groups, please fill out the inquiry list of security groups sgId field interface returned
	SgID string `json:"sgId" name:"sgId"`
	// Base64-encoded user script, which is executed after the k8s component is run. The user is required to guarantee the reentrant and retry logic of the script.
	UserScript string `json:"userScript" name:"userScript"`
}

// ToJSONString defines request to json format
func (r *AddClusterInstancesRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *AddClusterInstancesRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// AddClusterInstancesResponse defines the add cluster instances response
type AddClusterInstancesResponse struct {
	*tchttp.BaseResponse
	// Cluster data
	Data struct {
		RequestID   string   `json:"requestId" name:"requestId"`
		InstanceIDs []string `json:"instanceIds" name:"instanceIds"`
	} `json:"data"`
	// Public error code. 0 means success, other values indicates failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines response to json format
func (r *AddClusterInstancesResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines response from json format
func (r *AddClusterInstancesResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// ModifyClusterAttributesRequest defines the modify cluster attributes request
type ModifyClusterAttributesRequest struct {
	*tchttp.BaseRequest
	ClusterID   string `json:"clusterId" name:"clusterId"`
	ClusterName string `json:"clusterName" name:"clusterName"`
	ClusterDesc string `json:"clusterDesc" name:"clusterDesc"`
}

// ToJSONString defines request to json format
func (r *ModifyClusterAttributesRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *ModifyClusterAttributesRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// ModifyClusterAttributesResponse defines the response
type ModifyClusterAttributesResponse struct {
	*tchttp.BaseResponse
	// Public error code. 0 means success, other values indicates failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines request to json format
func (r *ModifyClusterAttributesResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *ModifyClusterAttributesResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// ModifyProjectIDRequest defines the modify project ID request
type ModifyProjectIDRequest struct {
	*tchttp.BaseRequest
	ClusterID string `json:"clusterId" name:"clusterId"`
	ProjectID int64  `json:"projectId" name:"projectId"`
}

// ToJSONString defines request to json format
func (r *ModifyProjectIDRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *ModifyProjectIDRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// ModifyProjectIDResponse defines the response
type ModifyProjectIDResponse struct {
	*tchttp.BaseResponse
	// Public error code. 0 means success, other values indicates failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines request to json format
func (r *ModifyProjectIDResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines request from json format
func (r *ModifyProjectIDResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DeleteClusterInstancesRequest defines the delete cluster instances request
type DeleteClusterInstancesRequest struct {
	*tchttp.BaseRequest
	ClusterID      string   `json:"clusterId" name:"clusterId"`
	InstanceIDs    []string `json:"instanceIds" name:"instanceIds"`
	NodeDeleteMode string   `json:"nodeDeleteMode" name:"nodeDeleteMode"`
}

// ToJSONString defines response to json format
func (r *DeleteClusterInstancesRequest) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines response from json format
func (r *DeleteClusterInstancesRequest) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

// DeleteClusterInstancesResponse defines the delete cluster instances response
type DeleteClusterInstancesResponse struct {
	*tchttp.BaseResponse
	// Public error code. 0 means success, other values indicates failure
	Code int64 `json:"code" name:"code"`
	// Module error message description, related to the interface
	Message string `json:"message" name:"message"`
	// Service side error code. Returns Success when successful,
	// and returns the reason for a specific business error when an error occurs
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

// ToJSONString defines response to json format
func (r *DeleteClusterInstancesResponse) ToJSONString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// FromJSONString defines response from json format
func (r *DeleteClusterInstancesResponse) FromJSONString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}
