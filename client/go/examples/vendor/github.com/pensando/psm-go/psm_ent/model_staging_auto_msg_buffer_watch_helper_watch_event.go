/*
 * Staging API reference
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

// StagingAutoMsgBufferWatchHelperWatchEvent struct for StagingAutoMsgBufferWatchHelperWatchEvent
type StagingAutoMsgBufferWatchHelperWatchEvent struct {
	Object *StagingBuffer `json:"object,omitempty"`
	Type *string `json:"type,omitempty"`
}

// NewStagingAutoMsgBufferWatchHelperWatchEvent instantiates a new StagingAutoMsgBufferWatchHelperWatchEvent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStagingAutoMsgBufferWatchHelperWatchEvent() *StagingAutoMsgBufferWatchHelperWatchEvent {
	this := StagingAutoMsgBufferWatchHelperWatchEvent{}
	return &this
}

// NewStagingAutoMsgBufferWatchHelperWatchEventWithDefaults instantiates a new StagingAutoMsgBufferWatchHelperWatchEvent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStagingAutoMsgBufferWatchHelperWatchEventWithDefaults() *StagingAutoMsgBufferWatchHelperWatchEvent {
	this := StagingAutoMsgBufferWatchHelperWatchEvent{}
	return &this
}

// GetObject returns the Object field value if set, zero value otherwise.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) GetObject() StagingBuffer {
	if o == nil || o.Object == nil {
		var ret StagingBuffer
		return ret
	}
	return *o.Object
}

// GetObjectOk returns a tuple with the Object field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) GetObjectOk() (*StagingBuffer, bool) {
	if o == nil || o.Object == nil {
		return nil, false
	}
	return o.Object, true
}

// HasObject returns a boolean if a field has been set.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) HasObject() bool {
	if o != nil && o.Object != nil {
		return true
	}

	return false
}

// SetObject gets a reference to the given StagingBuffer and assigns it to the Object field.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) SetObject(v StagingBuffer) {
	o.Object = &v
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) GetType() string {
	if o == nil || o.Type == nil {
		var ret string
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) GetTypeOk() (*string, bool) {
	if o == nil || o.Type == nil {
		return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) HasType() bool {
	if o != nil && o.Type != nil {
		return true
	}

	return false
}

// SetType gets a reference to the given string and assigns it to the Type field.
func (o *StagingAutoMsgBufferWatchHelperWatchEvent) SetType(v string) {
	o.Type = &v
}

func (o StagingAutoMsgBufferWatchHelperWatchEvent) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Object != nil {
		toSerialize["object"] = o.Object
	}
	if o.Type != nil {
		toSerialize["type"] = o.Type
	}
	return json.Marshal(toSerialize)
}

type NullableStagingAutoMsgBufferWatchHelperWatchEvent struct {
	value *StagingAutoMsgBufferWatchHelperWatchEvent
	isSet bool
}

func (v NullableStagingAutoMsgBufferWatchHelperWatchEvent) Get() *StagingAutoMsgBufferWatchHelperWatchEvent {
	return v.value
}

func (v *NullableStagingAutoMsgBufferWatchHelperWatchEvent) Set(val *StagingAutoMsgBufferWatchHelperWatchEvent) {
	v.value = val
	v.isSet = true
}

func (v NullableStagingAutoMsgBufferWatchHelperWatchEvent) IsSet() bool {
	return v.isSet
}

func (v *NullableStagingAutoMsgBufferWatchHelperWatchEvent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStagingAutoMsgBufferWatchHelperWatchEvent(val *StagingAutoMsgBufferWatchHelperWatchEvent) *NullableStagingAutoMsgBufferWatchHelperWatchEvent {
	return &NullableStagingAutoMsgBufferWatchHelperWatchEvent{value: val, isSet: true}
}

func (v NullableStagingAutoMsgBufferWatchHelperWatchEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStagingAutoMsgBufferWatchHelperWatchEvent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

