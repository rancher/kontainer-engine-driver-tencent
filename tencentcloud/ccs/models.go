package ccs

import (
	"encoding/json"

	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
)

type CreateClusterRequest struct {
	*tchttp.BaseRequest
	// 集群名称
	ClusterName *string `json:"clusterName" name:"clusterName"`
	// 集群描述
	ClusterDesc *string `json:"clusterDesc" name:"clusterDesc"`
	// 用于分配集群容器和服务 IP 的 CIDR，不得与 VPC CIDR 冲突，也不得与同 VPC 内其他集群 CIDR 冲突
	ClusterCIDR *string `json:"clusterCIDR" name:"clusterCIDR"`
	// 是否忽略 ClusterCIDR 冲突错误，默认为 0
	// 0：不忽略冲突（并返回错误）
	// 1：忽略冲突（继续创建）
	IgnoreClusterCIDRConflict *int `json:"ignoreClusterCIDRConflict" name:"ignoreClusterCIDRConflict"`
	//
	ZoneId *string `json:"zoneId" name:"zoneId"`
	//
	GoodsNum *int `json:"goodsNum" name:"goodsNum"`
	//
	Cpu *int `json:"cpu" name:"cpu"`
	//
	Mem *int `json:"mem" name:"mem"`
	// 系统名。CentOS7.2x86_64 或者 Ubuntu16.04.1 LTSx86_64，集群下所有节点都使用此系统，扩展节点也会自动使用此系统
	OsName *string `json:"osName" name:"osName"`
	//
	InstanceType *string `json:"instanceType" name:"instanceType"`
	//
	CvmType *string `json:"cvmType" name:"cvmType"`
	//
	RenewFlag *string `json:"renewFlag" name:"renewFlag"`
	//
	BandwidthType *string `json:"bandwidthType" name:"bandwidthType"`
	//
	Bandwidth *int `json:"bandwidth" name:"bandwidth"`
	//
	WanIp *int `json:"wanIp" name:"wanIp"`
	// 私有网络 ID，请填写 查询私有网络列表 接口中返回的 unVpcId ( 私有网络统一 ID )字段
	VpcId *string `json:"vpcId" name:"vpcId"`
	//
	SubnetId *string `json:"subnetId" name:"subnetId"`
	//
	IsVpcGateway *int `json:"isVpcGateway" name:"isVpcGateway"`
	//
	RootSize *int `json:"rootSize" name:"rootSize"`
	//
	RootType *string `json:"rootType" name:"rootType"`
	//
	StorageSize *int `json:"storageSize" name:"storageSize"`
	//
	StorageType *string `json:"storageType" name:"storageType"`
	//
	Password *string `json:"password" name:"password"`
	//
	KeyId *string `json:"keyId" name:"keyId"`
	//
	Period *string `json:"period" name:"period"`
	// 集群 Master 会占用一个 VPC 子网的 IP，该参数指定 Master 占用的 IP 所在哪个子网。该子网必须与集群存在同一个 VPC 内
	MasterSubnetId *string `json:"masterSubnetId" name:"masterSubnetId"`
	//
	SgId *string `json:"sgId" name:"sgId"`
	//
	UserScript *string `json:"userScript" name:"userScript"`
	// 集群版本
	ClusterVersion *string `json:"clusterVersion" name:"clusterVersion"`
	// 集群所属项目 ID
	ProjectId *int `json:"projectId" name:"projectId"`
}

func (r *CreateClusterRequest) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *CreateClusterRequest) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type CreateClusterResponse struct {
	*tchttp.BaseResponse
	// 公共错误码。0 表示成功，其他值表示失败
	Code *int `json:"code" name:"code"`
	// 模块错误信息描述，与接口相关
	Message *string `json:"message" name:"message"`
	// 业务侧错误码。成功时返回 Success，错误时返回具体业务错误原因
	CodeDesc *string `json:"codeDesc" name:"codeDesc"`
	// 集群参数
	Data struct {
		// 任务 ID
		RequestId *int `json:"requestId" name:"requestId"`
		// 集群 ID
		ClusterId *string `json:"clusterId" name:"clusterId"`
	} `json:"data"`
}

func (r *CreateClusterResponse) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *CreateClusterResponse) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type DescribeClusterInstancesRequest struct {
	*tchttp.BaseRequest
	//集群 ID
	ClusterId *string `json:"clusterId" name:"clusterId"`
	// 偏移量，默认 0
	Offset *string `json:"clusterDesc" name:"clusterDesc"`
	// 最大输出条数，默认 20
	Limit *string `json:"clusterCIDR" name:"clusterCIDR"`
	// 命名空间，默认为 default
	Namespace *string `json:"ignoreClusterCIDRConflict" name:"ignoreClusterCIDRConflict"`
	// 实例列表，默认为空
	instancesId *[]string `json:"zoneId" name:"zoneId"`
}

func (r *DescribeClusterInstancesRequest) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DescribeClusterInstancesRequest) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}
type DescribeClusterInstancesResponse struct {
	*tchttp.BaseResponse
	// 集群参数
	Data struct {
		// 集群节点总数
		TotalCount *int64 `json:"totalCount" name:"totalCount"`
		// 集群 ID
		Nodes *[] Node `json:"nodes" name:"nodes"`
	} `json:"data"`
	// 公共错误码。0 表示成功，其他值表示失败
	Code *int `json:"code" name:"code"`
	// 模块错误信息描述，与接口相关
	Message *string `json:"message" name:"message"`
	// 业务侧错误码。成功时返回 Success，错误时返回具体业务错误原因
	CodeDesc *string `json:"codeDesc" name:"codeDesc"`
}

func (r *DescribeClusterInstancesResponse) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DescribeClusterInstancesResponse) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}


type Node struct {
	InstanceId *string `json:"instanceId" name:"instanceId"`
	ProjectId *int `json:"projectId" name:"projectId"`
	InstanceName *string `json:"instanceName" name:"instanceName"`
	InstanceType *string `json:"instanceType" name:"instanceType"`
	KernelVersion *string `json:"kernelVersion" name:"kernelVersion"`
	PodCidr *string `json:"podCidr" name:"podCidr"`
	Cpu *int `json:"cpu" name:"cpu"`
	Mem *int `json:"mem" name:"mem"`
	Gpu *int `json:"gpu" name:"gpu"`
	WanIp *string `json:"wanIp" name:"wanIp"`
	LanIp *string `json:"lanIp" name:"lanIp"`
	OsImage *string `json:"osImage" name:"osImage"`
	IsNormal *int `json:"isNormal" name:"isNormal"`
	CvmState *int `json:"cvmState" name:"cvmState"`
	CvmPayMode *int `json:"cvmPayMode" name:"cvmPayMode"`
	NetworkPayMode *int `json:"networkPayMode" name:"networkPayMode"`
	CreatedAt *string `json:"createdAt" name:"createdAt"`
	InstanceCreateTime *string `json:"instanceCreateTime" name:"instanceCreateTime"`
	InstanceDeadlineTime *string `json:"instanceDeadlineTime" name:"instanceDeadlineTime"`
	ZoneId *int `json:"zoneId" name:"zoneId"`
	Zone *string `json:"zone" name:"zone"`
	AbnormalReason *AbnormalReason `json:"abnormalReason" name:"abnormalReason"`
	Labels *map[string] string `json:"labels" name:"labels"`
	AutoScalingGroupId *string `json:"autoScalingGroupId" name:"autoScalingGroupId"`
	Unschedulable *bool `json:"unschedulable" name:"unschedulable"`
	DrainStatus *string `json:"drainStatus" name:"drainStatus"`
}

type AbnormalReason struct {
	MemoryPressure *string `json:"MemoryPressure" name:"MemoryPressure"`
	OutOfDisk *string `json:"OutOfDisk" name:"OutOfDisk"`
	NetworkUnavailable *string `json:"NetworkUnavailable" name:"NetworkUnavailable"`
	Unknown *string `json:"Unknown" name:"Unknown"`
}

type DeleteClusterRequest struct {
	*tchttp.BaseRequest
	ClusterId *string `json:"clusterId" name:"clusterId"`
	// 集群节点删除方式，主要针对按量计费主机，包年包月主机只能做移除操作
	// RemoveOnly（仅移除）
	// Return（退还）
	// 默认为按量计费机器销毁，包年包月机器移除
	NodeDeleteMode *string `json:"nodeDeleteMode" name:"nodeDeleteMode"`
}

func (r *DeleteClusterRequest) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DeleteClusterRequest) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type DeleteClusterResponse struct {
	*tchttp.BaseResponse
	// 集群参数
	Data struct {
		// 唯一请求ID，每次请求都会返回。定位问题时需要提供该次请求的RequestId。
		RequestId *int `json:"requestId" name:"requestId"`
	} `json:"data"`
	// 公共错误码。0 表示成功，其他值表示失败
	Code *int `json:"code" name:"code"`
	// 模块错误信息描述，与接口相关
	Message *string `json:"message" name:"message"`
	// 业务侧错误码。成功时返回 Success，错误时返回具体业务错误原因
	CodeDesc *string `json:"codeDesc" name:"codeDesc"`
}

func (r *DeleteClusterResponse) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DeleteClusterResponse) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}


type DescribeClusterRequest struct {
	*tchttp.BaseRequest
	ClusterIds []string `json:"clusterIds" name:"clusterIds"`
	ClusterName string `json:"clusterName" name:"clusterName"`
	Status string `json:"status" name:"status"`
	OrderField string `json:"orderField" name:"orderField"`
	OrderType string `json:"orderType" name:"orderType"`
	Offset int `json:"offset" name:"offset"`
	Limit int `json:"limit" name:"limit"`
}

func (r *DescribeClusterRequest) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DescribeClusterRequest) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type DescribeClusterResponse struct {
	*tchttp.BaseResponse
	// 集群参数
	Data struct {
		TotalCount int64 `json:"totalCount" name:"totalCount"`
		Clusters []Cluster `json:"clusters" name:"clusters"`
	} `json:"data"`
	// 公共错误码。0 表示成功，其他值表示失败
	Code int `json:"code" name:"code"`
	// 模块错误信息描述，与接口相关
	Message string `json:"message" name:"message"`
	// 业务侧错误码。成功时返回 Success，错误时返回具体业务错误原因
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

func (r *DescribeClusterResponse) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DescribeClusterResponse) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type Cluster struct {
	ClusterId string `json:"clusterId" name:"clusterId"`
	ClusterName string `json:"clusterName" name:"clusterName"`
	Description string `json:"description" name:"description"`
	ClusterCIDR string `json:"clusterCIDR" name:"clusterCIDR"`
	UnVpcId string `json:"unVpcId" name:"unVpcId"`
	VpcId int64 `json:"vpcId" name:"vpcId"`
	Status string `json:"status" name:"status"`
	NodeNum int64 `json:"nodeNum" name:"nodeNum"`
	NodeStatus string `json:"nodeStatus" name:"nodeStatus"`
	TotalCpu int64 `json:"totalCpu" name:"totalCpu"`
	TotalMem int64 `json:"totalMem" name:"totalMem"`
	OS string `json:"os" name:"os"`
	CreatedAt int64 `json:"createdAt" name:"createdAt"`
	UpdatedAt int64 `json:"updatedAt" name:"updatedAt"`
	RegionId string `json:"regionId" name:"regionId"`
	Region string `json:"region" name:"region"`
	K8sVersion string `json:"k8sVersion" name:"k8sVersion"`
	ClusterExternalEndpoint string `json:"clusterExternalEndpoint" name:"clusterExternalEndpoint"`
	ProjectId int64 `json:"projectId" name:"projectId"`
}

type DescribeClusterSecurityInfoRequest struct {
	*tchttp.BaseRequest
	ClusterId *string `json:"clusterId" name:"clusterId"`
}

func (r *DescribeClusterSecurityInfoRequest) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DescribeClusterSecurityInfoRequest) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type DescribeClusterSecurityInfoResponse struct {
	*tchttp.BaseResponse
	// 集群参数
	Data struct {
		UserName string `json:"userName" name:"userName"`
		Password string `json:"password" name:"password"`
		CertificationAuthority string `json:"certificationAuthority" name:"certificationAuthority"`
		ClusterExternalEndpoint string `json:"clusterExternalEndpoint" name:"clusterExternalEndpoint"`
		PgwEndpoint string `json:"pgwEndpoint" name:"pgwEndpoint"`
		Domain string `json:"domain" name:"domain"`
	} `json:"data"`
	// 公共错误码。0 表示成功，其他值表示失败
	Code int `json:"code" name:"code"`
	// 模块错误信息描述，与接口相关
	Message string `json:"message" name:"message"`
	// 业务侧错误码。成功时返回 Success，错误时返回具体业务错误原因
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

func (r *DescribeClusterSecurityInfoResponse) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *DescribeClusterSecurityInfoResponse) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type OperateClusterVipRequest struct {
	*tchttp.BaseRequest
	ClusterId string `json:"clusterId" name:"clusterId"`
	Operation string `json:"operation" name:"operation"`
}

func (r *OperateClusterVipRequest) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *OperateClusterVipRequest) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}

type OperateClusterVipResponse struct {
	*tchttp.BaseResponse
	// 集群参数
	Data struct {
		RequestId string `json:"requestId" name:"requestId"`
	} `json:"data"`
	// 公共错误码。0 表示成功，其他值表示失败
	Code int `json:"code" name:"code"`
	// 模块错误信息描述，与接口相关
	Message string `json:"message" name:"message"`
	// 业务侧错误码。成功时返回 Success，错误时返回具体业务错误原因
	CodeDesc string `json:"codeDesc" name:"codeDesc"`
}

func (r *OperateClusterVipResponse) ToJsonString() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r *OperateClusterVipResponse) FromJsonString(s string) error {
	return json.Unmarshal([]byte(s), &r)
}
