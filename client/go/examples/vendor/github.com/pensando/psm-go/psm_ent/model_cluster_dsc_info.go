/*
 * Cluster API reference
 *
 * Service name  
 *
 * API version: 1.0.0
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package psm_ent

import (
	"encoding/json"
)

// ClusterDSCInfo Distributed service card (DSC) subsystem information.
type ClusterDSCInfo struct {
	BiosInfo *ClusterBiosInfo `json:"bios-info,omitempty"`
	CpuInfo *ClusterCPUInfo `json:"cpu-info,omitempty"`
	MemoryInfo *ClusterMemInfo `json:"memory-info,omitempty"`
	OsInfo *ClusterOsInfo `json:"os-info,omitempty"`
	StorageInfo *ClusterStorageInfo `json:"storage-info,omitempty"`
}

// NewClusterDSCInfo instantiates a new ClusterDSCInfo object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewClusterDSCInfo() *ClusterDSCInfo {
	this := ClusterDSCInfo{}
	return &this
}

// NewClusterDSCInfoWithDefaults instantiates a new ClusterDSCInfo object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewClusterDSCInfoWithDefaults() *ClusterDSCInfo {
	this := ClusterDSCInfo{}
	return &this
}

// GetBiosInfo returns the BiosInfo field value if set, zero value otherwise.
func (o *ClusterDSCInfo) GetBiosInfo() ClusterBiosInfo {
	if o == nil || o.BiosInfo == nil {
		var ret ClusterBiosInfo
		return ret
	}
	return *o.BiosInfo
}

// GetBiosInfoOk returns a tuple with the BiosInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ClusterDSCInfo) GetBiosInfoOk() (*ClusterBiosInfo, bool) {
	if o == nil || o.BiosInfo == nil {
		return nil, false
	}
	return o.BiosInfo, true
}

// HasBiosInfo returns a boolean if a field has been set.
func (o *ClusterDSCInfo) HasBiosInfo() bool {
	if o != nil && o.BiosInfo != nil {
		return true
	}

	return false
}

// SetBiosInfo gets a reference to the given ClusterBiosInfo and assigns it to the BiosInfo field.
func (o *ClusterDSCInfo) SetBiosInfo(v ClusterBiosInfo) {
	o.BiosInfo = &v
}

// GetCpuInfo returns the CpuInfo field value if set, zero value otherwise.
func (o *ClusterDSCInfo) GetCpuInfo() ClusterCPUInfo {
	if o == nil || o.CpuInfo == nil {
		var ret ClusterCPUInfo
		return ret
	}
	return *o.CpuInfo
}

// GetCpuInfoOk returns a tuple with the CpuInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ClusterDSCInfo) GetCpuInfoOk() (*ClusterCPUInfo, bool) {
	if o == nil || o.CpuInfo == nil {
		return nil, false
	}
	return o.CpuInfo, true
}

// HasCpuInfo returns a boolean if a field has been set.
func (o *ClusterDSCInfo) HasCpuInfo() bool {
	if o != nil && o.CpuInfo != nil {
		return true
	}

	return false
}

// SetCpuInfo gets a reference to the given ClusterCPUInfo and assigns it to the CpuInfo field.
func (o *ClusterDSCInfo) SetCpuInfo(v ClusterCPUInfo) {
	o.CpuInfo = &v
}

// GetMemoryInfo returns the MemoryInfo field value if set, zero value otherwise.
func (o *ClusterDSCInfo) GetMemoryInfo() ClusterMemInfo {
	if o == nil || o.MemoryInfo == nil {
		var ret ClusterMemInfo
		return ret
	}
	return *o.MemoryInfo
}

// GetMemoryInfoOk returns a tuple with the MemoryInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ClusterDSCInfo) GetMemoryInfoOk() (*ClusterMemInfo, bool) {
	if o == nil || o.MemoryInfo == nil {
		return nil, false
	}
	return o.MemoryInfo, true
}

// HasMemoryInfo returns a boolean if a field has been set.
func (o *ClusterDSCInfo) HasMemoryInfo() bool {
	if o != nil && o.MemoryInfo != nil {
		return true
	}

	return false
}

// SetMemoryInfo gets a reference to the given ClusterMemInfo and assigns it to the MemoryInfo field.
func (o *ClusterDSCInfo) SetMemoryInfo(v ClusterMemInfo) {
	o.MemoryInfo = &v
}

// GetOsInfo returns the OsInfo field value if set, zero value otherwise.
func (o *ClusterDSCInfo) GetOsInfo() ClusterOsInfo {
	if o == nil || o.OsInfo == nil {
		var ret ClusterOsInfo
		return ret
	}
	return *o.OsInfo
}

// GetOsInfoOk returns a tuple with the OsInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ClusterDSCInfo) GetOsInfoOk() (*ClusterOsInfo, bool) {
	if o == nil || o.OsInfo == nil {
		return nil, false
	}
	return o.OsInfo, true
}

// HasOsInfo returns a boolean if a field has been set.
func (o *ClusterDSCInfo) HasOsInfo() bool {
	if o != nil && o.OsInfo != nil {
		return true
	}

	return false
}

// SetOsInfo gets a reference to the given ClusterOsInfo and assigns it to the OsInfo field.
func (o *ClusterDSCInfo) SetOsInfo(v ClusterOsInfo) {
	o.OsInfo = &v
}

// GetStorageInfo returns the StorageInfo field value if set, zero value otherwise.
func (o *ClusterDSCInfo) GetStorageInfo() ClusterStorageInfo {
	if o == nil || o.StorageInfo == nil {
		var ret ClusterStorageInfo
		return ret
	}
	return *o.StorageInfo
}

// GetStorageInfoOk returns a tuple with the StorageInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ClusterDSCInfo) GetStorageInfoOk() (*ClusterStorageInfo, bool) {
	if o == nil || o.StorageInfo == nil {
		return nil, false
	}
	return o.StorageInfo, true
}

// HasStorageInfo returns a boolean if a field has been set.
func (o *ClusterDSCInfo) HasStorageInfo() bool {
	if o != nil && o.StorageInfo != nil {
		return true
	}

	return false
}

// SetStorageInfo gets a reference to the given ClusterStorageInfo and assigns it to the StorageInfo field.
func (o *ClusterDSCInfo) SetStorageInfo(v ClusterStorageInfo) {
	o.StorageInfo = &v
}

func (o ClusterDSCInfo) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.BiosInfo != nil {
		toSerialize["bios-info"] = o.BiosInfo
	}
	if o.CpuInfo != nil {
		toSerialize["cpu-info"] = o.CpuInfo
	}
	if o.MemoryInfo != nil {
		toSerialize["memory-info"] = o.MemoryInfo
	}
	if o.OsInfo != nil {
		toSerialize["os-info"] = o.OsInfo
	}
	if o.StorageInfo != nil {
		toSerialize["storage-info"] = o.StorageInfo
	}
	return json.Marshal(toSerialize)
}

type NullableClusterDSCInfo struct {
	value *ClusterDSCInfo
	isSet bool
}

func (v NullableClusterDSCInfo) Get() *ClusterDSCInfo {
	return v.value
}

func (v *NullableClusterDSCInfo) Set(val *ClusterDSCInfo) {
	v.value = val
	v.isSet = true
}

func (v NullableClusterDSCInfo) IsSet() bool {
	return v.isSet
}

func (v *NullableClusterDSCInfo) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableClusterDSCInfo(val *ClusterDSCInfo) *NullableClusterDSCInfo {
	return &NullableClusterDSCInfo{value: val, isSet: true}
}

func (v NullableClusterDSCInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableClusterDSCInfo) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

