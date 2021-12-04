/*
 * Monitoring API reference
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

// MonitoringAppProtoSelector Application/protocol selector.
type MonitoringAppProtoSelector struct {
	// Apps - E.g. [\"Redis\"].
	Applications *[]string `json:"applications,omitempty"`
	// ports - Includes protocol name and port Eg [\"tcp/1234\", \"udp\"]. Should be a valid layer 3 or layer 4 protocol and port range. any is also allowed.
	ProtoPorts *[]string `json:"proto-ports,omitempty"`
}

// NewMonitoringAppProtoSelector instantiates a new MonitoringAppProtoSelector object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewMonitoringAppProtoSelector() *MonitoringAppProtoSelector {
	this := MonitoringAppProtoSelector{}
	return &this
}

// NewMonitoringAppProtoSelectorWithDefaults instantiates a new MonitoringAppProtoSelector object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewMonitoringAppProtoSelectorWithDefaults() *MonitoringAppProtoSelector {
	this := MonitoringAppProtoSelector{}
	return &this
}

// GetApplications returns the Applications field value if set, zero value otherwise.
func (o *MonitoringAppProtoSelector) GetApplications() []string {
	if o == nil || o.Applications == nil {
		var ret []string
		return ret
	}
	return *o.Applications
}

// GetApplicationsOk returns a tuple with the Applications field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MonitoringAppProtoSelector) GetApplicationsOk() (*[]string, bool) {
	if o == nil || o.Applications == nil {
		return nil, false
	}
	return o.Applications, true
}

// HasApplications returns a boolean if a field has been set.
func (o *MonitoringAppProtoSelector) HasApplications() bool {
	if o != nil && o.Applications != nil {
		return true
	}

	return false
}

// SetApplications gets a reference to the given []string and assigns it to the Applications field.
func (o *MonitoringAppProtoSelector) SetApplications(v []string) {
	o.Applications = &v
}

// GetProtoPorts returns the ProtoPorts field value if set, zero value otherwise.
func (o *MonitoringAppProtoSelector) GetProtoPorts() []string {
	if o == nil || o.ProtoPorts == nil {
		var ret []string
		return ret
	}
	return *o.ProtoPorts
}

// GetProtoPortsOk returns a tuple with the ProtoPorts field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MonitoringAppProtoSelector) GetProtoPortsOk() (*[]string, bool) {
	if o == nil || o.ProtoPorts == nil {
		return nil, false
	}
	return o.ProtoPorts, true
}

// HasProtoPorts returns a boolean if a field has been set.
func (o *MonitoringAppProtoSelector) HasProtoPorts() bool {
	if o != nil && o.ProtoPorts != nil {
		return true
	}

	return false
}

// SetProtoPorts gets a reference to the given []string and assigns it to the ProtoPorts field.
func (o *MonitoringAppProtoSelector) SetProtoPorts(v []string) {
	o.ProtoPorts = &v
}

func (o MonitoringAppProtoSelector) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Applications != nil {
		toSerialize["applications"] = o.Applications
	}
	if o.ProtoPorts != nil {
		toSerialize["proto-ports"] = o.ProtoPorts
	}
	return json.Marshal(toSerialize)
}

type NullableMonitoringAppProtoSelector struct {
	value *MonitoringAppProtoSelector
	isSet bool
}

func (v NullableMonitoringAppProtoSelector) Get() *MonitoringAppProtoSelector {
	return v.value
}

func (v *NullableMonitoringAppProtoSelector) Set(val *MonitoringAppProtoSelector) {
	v.value = val
	v.isSet = true
}

func (v NullableMonitoringAppProtoSelector) IsSet() bool {
	return v.isSet
}

func (v *NullableMonitoringAppProtoSelector) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableMonitoringAppProtoSelector(val *MonitoringAppProtoSelector) *NullableMonitoringAppProtoSelector {
	return &NullableMonitoringAppProtoSelector{value: val, isSet: true}
}

func (v NullableMonitoringAppProtoSelector) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableMonitoringAppProtoSelector) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

