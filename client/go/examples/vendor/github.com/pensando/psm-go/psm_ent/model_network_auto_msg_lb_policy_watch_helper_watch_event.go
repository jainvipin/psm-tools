/*
 * Network API reference
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

// NetworkAutoMsgLbPolicyWatchHelperWatchEvent struct for NetworkAutoMsgLbPolicyWatchHelperWatchEvent
type NetworkAutoMsgLbPolicyWatchHelperWatchEvent struct {
	Object *NetworkLbPolicy `json:"object,omitempty"`
	Type *string `json:"type,omitempty"`
}

// NewNetworkAutoMsgLbPolicyWatchHelperWatchEvent instantiates a new NetworkAutoMsgLbPolicyWatchHelperWatchEvent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewNetworkAutoMsgLbPolicyWatchHelperWatchEvent() *NetworkAutoMsgLbPolicyWatchHelperWatchEvent {
	this := NetworkAutoMsgLbPolicyWatchHelperWatchEvent{}
	return &this
}

// NewNetworkAutoMsgLbPolicyWatchHelperWatchEventWithDefaults instantiates a new NetworkAutoMsgLbPolicyWatchHelperWatchEvent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewNetworkAutoMsgLbPolicyWatchHelperWatchEventWithDefaults() *NetworkAutoMsgLbPolicyWatchHelperWatchEvent {
	this := NetworkAutoMsgLbPolicyWatchHelperWatchEvent{}
	return &this
}

// GetObject returns the Object field value if set, zero value otherwise.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) GetObject() NetworkLbPolicy {
	if o == nil || o.Object == nil {
		var ret NetworkLbPolicy
		return ret
	}
	return *o.Object
}

// GetObjectOk returns a tuple with the Object field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) GetObjectOk() (*NetworkLbPolicy, bool) {
	if o == nil || o.Object == nil {
		return nil, false
	}
	return o.Object, true
}

// HasObject returns a boolean if a field has been set.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) HasObject() bool {
	if o != nil && o.Object != nil {
		return true
	}

	return false
}

// SetObject gets a reference to the given NetworkLbPolicy and assigns it to the Object field.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) SetObject(v NetworkLbPolicy) {
	o.Object = &v
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) GetType() string {
	if o == nil || o.Type == nil {
		var ret string
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) GetTypeOk() (*string, bool) {
	if o == nil || o.Type == nil {
		return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) HasType() bool {
	if o != nil && o.Type != nil {
		return true
	}

	return false
}

// SetType gets a reference to the given string and assigns it to the Type field.
func (o *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) SetType(v string) {
	o.Type = &v
}

func (o NetworkAutoMsgLbPolicyWatchHelperWatchEvent) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Object != nil {
		toSerialize["object"] = o.Object
	}
	if o.Type != nil {
		toSerialize["type"] = o.Type
	}
	return json.Marshal(toSerialize)
}

type NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent struct {
	value *NetworkAutoMsgLbPolicyWatchHelperWatchEvent
	isSet bool
}

func (v NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent) Get() *NetworkAutoMsgLbPolicyWatchHelperWatchEvent {
	return v.value
}

func (v *NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent) Set(val *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) {
	v.value = val
	v.isSet = true
}

func (v NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent) IsSet() bool {
	return v.isSet
}

func (v *NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent(val *NetworkAutoMsgLbPolicyWatchHelperWatchEvent) *NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent {
	return &NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent{value: val, isSet: true}
}

func (v NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableNetworkAutoMsgLbPolicyWatchHelperWatchEvent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

