/*
 * Security API reference
 *
 *  
 *
 * API version: 1.0.0
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package psm_ent

import (
	"encoding/json"
)

// SecuritySecurityGroupStatus security group status.
type SecuritySecurityGroupStatus struct {
	// list of all policies attached to this security group.
	Policies *[]string `json:"Policies,omitempty"`
	// list of workloads that are part of this security group.
	Workloads *[]string `json:"workloads,omitempty"`
}

// NewSecuritySecurityGroupStatus instantiates a new SecuritySecurityGroupStatus object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSecuritySecurityGroupStatus() *SecuritySecurityGroupStatus {
	this := SecuritySecurityGroupStatus{}
	return &this
}

// NewSecuritySecurityGroupStatusWithDefaults instantiates a new SecuritySecurityGroupStatus object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSecuritySecurityGroupStatusWithDefaults() *SecuritySecurityGroupStatus {
	this := SecuritySecurityGroupStatus{}
	return &this
}

// GetPolicies returns the Policies field value if set, zero value otherwise.
func (o *SecuritySecurityGroupStatus) GetPolicies() []string {
	if o == nil || o.Policies == nil {
		var ret []string
		return ret
	}
	return *o.Policies
}

// GetPoliciesOk returns a tuple with the Policies field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SecuritySecurityGroupStatus) GetPoliciesOk() (*[]string, bool) {
	if o == nil || o.Policies == nil {
		return nil, false
	}
	return o.Policies, true
}

// HasPolicies returns a boolean if a field has been set.
func (o *SecuritySecurityGroupStatus) HasPolicies() bool {
	if o != nil && o.Policies != nil {
		return true
	}

	return false
}

// SetPolicies gets a reference to the given []string and assigns it to the Policies field.
func (o *SecuritySecurityGroupStatus) SetPolicies(v []string) {
	o.Policies = &v
}

// GetWorkloads returns the Workloads field value if set, zero value otherwise.
func (o *SecuritySecurityGroupStatus) GetWorkloads() []string {
	if o == nil || o.Workloads == nil {
		var ret []string
		return ret
	}
	return *o.Workloads
}

// GetWorkloadsOk returns a tuple with the Workloads field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SecuritySecurityGroupStatus) GetWorkloadsOk() (*[]string, bool) {
	if o == nil || o.Workloads == nil {
		return nil, false
	}
	return o.Workloads, true
}

// HasWorkloads returns a boolean if a field has been set.
func (o *SecuritySecurityGroupStatus) HasWorkloads() bool {
	if o != nil && o.Workloads != nil {
		return true
	}

	return false
}

// SetWorkloads gets a reference to the given []string and assigns it to the Workloads field.
func (o *SecuritySecurityGroupStatus) SetWorkloads(v []string) {
	o.Workloads = &v
}

func (o SecuritySecurityGroupStatus) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Policies != nil {
		toSerialize["Policies"] = o.Policies
	}
	if o.Workloads != nil {
		toSerialize["workloads"] = o.Workloads
	}
	return json.Marshal(toSerialize)
}

type NullableSecuritySecurityGroupStatus struct {
	value *SecuritySecurityGroupStatus
	isSet bool
}

func (v NullableSecuritySecurityGroupStatus) Get() *SecuritySecurityGroupStatus {
	return v.value
}

func (v *NullableSecuritySecurityGroupStatus) Set(val *SecuritySecurityGroupStatus) {
	v.value = val
	v.isSet = true
}

func (v NullableSecuritySecurityGroupStatus) IsSet() bool {
	return v.isSet
}

func (v *NullableSecuritySecurityGroupStatus) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSecuritySecurityGroupStatus(val *SecuritySecurityGroupStatus) *NullableSecuritySecurityGroupStatus {
	return &NullableSecuritySecurityGroupStatus{value: val, isSet: true}
}

func (v NullableSecuritySecurityGroupStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSecuritySecurityGroupStatus) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

