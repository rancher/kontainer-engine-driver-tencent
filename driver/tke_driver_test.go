package driver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
)

func TestGetStateFromOld(t *testing.T) {
	state := &state{
		ClusterName:               "test",
		ClusterDesc:               "testDesc",
		ClusterCIDR:               "172.16.0.0/16",
		IgnoreClusterCIDRConflict: 0,
		ZoneID:                    "100003",
		GoodsNum:                  1,
		CPU:                       2,
		Mem:                       4,
		OsName:                    "ubuntu16.04.1 LTSx86_64",
		InstanceType:              "S2.MEDIUM4",
		CvmType:                   "PayByHour",
		RenewFlag:                 "",
		BandwidthType:             "PayByHour",
		Bandwidth:                 10,
		WanIP:                     1,
		VpcID:                     "vpc-hdosln5x",
		SubnetID:                  "subnet-82sy1p20",
		IsVpcGateway:              0,
		RootSize:                  100,
		RootType:                  "CLOUD_PREMIUM",
		StorageSize:               100,
		StorageType:               "CLOUD_PREMIUM",
		Password:                  "",
		KeyID:                     "skey-bq0n7zb3",
		Period:                    0,
		MasterSubnetID:            "",
		SgID:                      "sg-rs3rzezp",
		UserScript:                "",
		ClusterVersion:            "1.12.4",
		ProjectID:                 0,
	}
	assert.Nil(t, state.CreateClusterRequest)
	state = getStateFromOld(state)
	assert.NotNil(t, state.CreateClusterRequest)

	assert.Equal(t, *state.CreateClusterRequest.ClusterBasicSettings.ClusterName, state.ClusterName)
	assert.Equal(t, *state.CreateClusterRequest.ClusterBasicSettings.ClusterDescription, state.ClusterDesc)
	assert.Equal(t, *state.CreateClusterRequest.ClusterCIDRSettings.ClusterCIDR, state.ClusterCIDR)
	assert.Equal(t, *state.CreateClusterRequest.ClusterCIDRSettings.IgnoreClusterCIDRConflict, getBoolean(state.IgnoreClusterCIDRConflict))
	assert.Equal(t, *state.CreateClusterRequest.ClusterBasicSettings.ClusterOs, state.OsName)
	assert.Equal(t, *state.CreateClusterRequest.ClusterBasicSettings.VpcId, state.VpcID)
	assert.Equal(t, *state.CreateClusterRequest.ClusterBasicSettings.ClusterVersion, state.ClusterVersion)
	assert.Equal(t, *state.CreateClusterRequest.ClusterBasicSettings.ProjectId, state.ProjectID)

	runInstancesPara := &cvm.RunInstancesRequest{}
	runInstancesPara.FromJsonString(*state.CreateClusterRequest.RunInstancesForNode[0].RunInstancesPara[0])

	assert.Equal(t, *runInstancesPara.Placement.Zone, state.ZoneID)
	assert.Equal(t, *runInstancesPara.InstanceType, state.InstanceType)
	assert.Equal(t, *runInstancesPara.InstanceChargeType, state.CvmType)
	assert.Equal(t, *runInstancesPara.InternetAccessible.InternetChargeType, state.BandwidthType)
	assert.Equal(t, *runInstancesPara.InternetAccessible.InternetMaxBandwidthOut, state.Bandwidth)
	assert.Equal(t, *runInstancesPara.InternetAccessible.PublicIpAssigned, getBoolean(state.WanIP))
	assert.Equal(t, *runInstancesPara.VirtualPrivateCloud.SubnetId, state.SubnetID)
	assert.Equal(t, *runInstancesPara.VirtualPrivateCloud.AsVpcGateway, getBoolean(state.IsVpcGateway))
	assert.Equal(t, *runInstancesPara.SystemDisk.DiskSize, state.RootSize)
	assert.Equal(t, *runInstancesPara.SystemDisk.DiskType, state.RootType)
	assert.Equal(t, *runInstancesPara.DataDisks[0].DiskSize, state.StorageSize)
	assert.Equal(t, *runInstancesPara.DataDisks[0].DiskType, state.StorageType)
	assert.Equal(t, *runInstancesPara.LoginSettings.KeyIds[0], state.KeyID)
	assert.Equal(t, *runInstancesPara.SecurityGroupIds[0], state.SgID)
}
