package ccs

import (
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

const APIVersion = ""

type Client struct {
	common.Client
}

func NewClientWithSecretId(secretId, secretKey, region string) (client *Client, err error) {
	cpf := profile.NewClientProfile()
	client = &Client{}
	client.Init(region).WithSecretId(secretId, secretKey).WithProfile(cpf)
	return
}

func NewClient(credential *common.Credential, region string, clientProfile *profile.ClientProfile) (client *Client, err error) {
	client = &Client{}
	client.Init(region).
		WithSecretId(credential.SecretId, credential.SecretKey).
		WithProfile(clientProfile)
	return
}

func NewCreateClusterRequest(emptyCluster bool) (request *CreateClusterRequest) {
	request = &CreateClusterRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	if emptyCluster {
		request.Init().WithApiInfo("ccs", APIVersion, "CreateEmptyCluster")
	} else {
		request.Init().WithApiInfo("ccs", APIVersion, "CreateCluster")
	}
	return
}

func NewCreateClusterResponse() (response *CreateClusterResponse) {
	response = &CreateClusterResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// CreateCluster creates a container cluster
func (c *Client) CreateCluster(request *CreateClusterRequest, emptyCluster bool) (response *CreateClusterResponse, err error) {
	if request == nil {
		request = NewCreateClusterRequest(emptyCluster)
	}
	response = NewCreateClusterResponse()
	err = c.Send(request, response)
	return
}

func NewDeleteClusterRequest() (request *DeleteClusterRequest) {
	request = &DeleteClusterRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", APIVersion, "DeleteCluster")
	return
}

func NewDeleteContainerInstanceResponse() (response *DeleteClusterResponse) {
	response = &DeleteClusterResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// DeleteCluster removes the cluster
func (c *Client) DeleteCluster(request *DeleteClusterRequest) (response *DeleteClusterResponse, err error) {
	if request == nil {
		request = NewDeleteClusterRequest()
	}
	response = NewDeleteContainerInstanceResponse()
	err = c.Send(request, response)
	return
}

func NewDescribeClusterInstancesRequest() (request *DescribeClusterInstancesRequest) {
	request = &DescribeClusterInstancesRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", APIVersion, "DescribeClusterInstances")
	return
}

func NewDescribeClusterInstancesResponse() (response *DescribeClusterInstancesResponse) {
	response = &DescribeClusterInstancesResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// DescribeContainerInstance get the cluster instances
func (c *Client) DescribeClusterInstance(request *DescribeClusterInstancesRequest) (response *DescribeClusterInstancesResponse, err error) {
	if request == nil {
		request = NewDescribeClusterInstancesRequest()
	}
	response = NewDescribeClusterInstancesResponse()
	err = c.Send(request, response)
	return
}

func NewDescribeClusterRequest() (request *DescribeClusterRequest) {
	request = &DescribeClusterRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", APIVersion, "DescribeCluster")
	return
}

func NewDescribeClusterResponse() (response *DescribeClusterResponse) {
	response = &DescribeClusterResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// DescribeCluster get the cluster details
func (c *Client) DescribeCluster(request *DescribeClusterRequest) (response *DescribeClusterResponse, err error) {
	if request == nil {
		request = NewDescribeClusterRequest()
	}
	response = NewDescribeClusterResponse()
	err = c.Send(request, response)
	return
}

func NewDescribeClusterSecurityInfoRequest() (request *DescribeClusterSecurityInfoRequest) {
	request = &DescribeClusterSecurityInfoRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", APIVersion, "DescribeClusterSecurityInfo")
	return
}

func NewDescribeClusterSecurityInfoResponse() (response *DescribeClusterSecurityInfoResponse) {
	response = &DescribeClusterSecurityInfoResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// DescribeCluster get the cluster details
func (c *Client) DescribeClusterSecurityInfo(request *DescribeClusterSecurityInfoRequest) (response *DescribeClusterSecurityInfoResponse, err error) {
	if request == nil {
		request = NewDescribeClusterSecurityInfoRequest()
	}
	response = NewDescribeClusterSecurityInfoResponse()
	err = c.Send(request, response)
	return
}


func NewOperateClusterVipRequest() (request *OperateClusterVipRequest) {
	request = &OperateClusterVipRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", APIVersion, "OperateClusterVip")
	return
}

func NewOperateClusterVipResponse() (response *OperateClusterVipResponse) {
	response = &OperateClusterVipResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// OperateClusterVip create or remove cluster vip
func (c *Client) OperateClusterVip(request *OperateClusterVipRequest) (response *OperateClusterVipResponse, err error) {
	if request == nil {
		request = NewOperateClusterVipRequest()
	}
	response = NewOperateClusterVipResponse()
	err = c.Send(request, response)
	return
}
