package ccs

import (
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

const apiVersion = ""

// Client defines the client struct
type Client struct {
	common.Client
}

// NewClient init new tke client
func NewClient(credential *common.Credential, region string, clientProfile *profile.ClientProfile) (client *Client, err error) {
	client = &Client{}
	client.Init(region).
		WithSecretId(credential.SecretId, credential.SecretKey).
		WithProfile(clientProfile)
	return
}

// NewCreateClusterRequest defines create cluster request
func NewCreateClusterRequest(emptyCluster bool) (request *CreateClusterRequest) {
	request = &CreateClusterRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	if emptyCluster {
		request.Init().WithApiInfo("ccs", apiVersion, "CreateEmptyCluster")
	} else {
		request.Init().WithApiInfo("ccs", apiVersion, "CreateCluster")
	}
	return
}

// NewCreateClusterResponse defines create cluster response
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

// NewDeleteClusterRequest defines delete cluster request
func NewDeleteClusterRequest() (request *DeleteClusterRequest) {
	request = &DeleteClusterRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", apiVersion, "DeleteCluster")
	return
}

// NewDeleteContainerInstanceResponse defines delete cluster response
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

// NewDescribeClusterInstancesRequest defines get driver cluster request
func NewDescribeClusterInstancesRequest() (request *DescribeClusterInstancesRequest) {
	request = &DescribeClusterInstancesRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", apiVersion, "DescribeClusterInstances")
	return
}

// NewDescribeClusterInstancesResponse defines get driver cluster response
func NewDescribeClusterInstancesResponse() (response *DescribeClusterInstancesResponse) {
	response = &DescribeClusterInstancesResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// DescribeClusterInstance get the cluster instances
func (c *Client) DescribeClusterInstance(request *DescribeClusterInstancesRequest) (response *DescribeClusterInstancesResponse, err error) {
	if request == nil {
		request = NewDescribeClusterInstancesRequest()
	}
	response = NewDescribeClusterInstancesResponse()
	err = c.Send(request, response)
	return
}

// NewDescribeClusterRequest defines driver cluster request
func NewDescribeClusterRequest() (request *DescribeClusterRequest) {
	request = &DescribeClusterRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", apiVersion, "DescribeCluster")
	return
}

// NewDescribeClusterResponse defines driver cluster response
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

// NewDescribeClusterSecurityInfoRequest defines driver cluster security info request
func NewDescribeClusterSecurityInfoRequest() (request *DescribeClusterSecurityInfoRequest) {
	request = &DescribeClusterSecurityInfoRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", apiVersion, "DescribeClusterSecurityInfo")
	return
}

// NewDescribeClusterSecurityInfoResponse defines driver cluster security info response
func NewDescribeClusterSecurityInfoResponse() (response *DescribeClusterSecurityInfoResponse) {
	response = &DescribeClusterSecurityInfoResponse{
		BaseResponse: &tchttp.BaseResponse{},
	}
	return
}

// DescribeClusterSecurityInfo get the cluster details
func (c *Client) DescribeClusterSecurityInfo(request *DescribeClusterSecurityInfoRequest) (response *DescribeClusterSecurityInfoResponse, err error) {
	if request == nil {
		request = NewDescribeClusterSecurityInfoRequest()
	}
	response = NewDescribeClusterSecurityInfoResponse()
	err = c.Send(request, response)
	return
}

// NewOperateClusterVipRequest defines driver cluster vip request
func NewOperateClusterVipRequest() (request *OperateClusterVipRequest) {
	request = &OperateClusterVipRequest{
		BaseRequest: &tchttp.BaseRequest{},
	}
	request.Init().WithApiInfo("cis", apiVersion, "OperateClusterVip")
	return
}

// NewOperateClusterVipResponse defines driver cluster vip response
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
