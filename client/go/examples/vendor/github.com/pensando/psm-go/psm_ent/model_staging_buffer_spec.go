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

// StagingBufferSpec struct for StagingBufferSpec
type StagingBufferSpec struct {
	Contact *string `json:"Contact,omitempty"`
}

// NewStagingBufferSpec instantiates a new StagingBufferSpec object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStagingBufferSpec() *StagingBufferSpec {
	this := StagingBufferSpec{}
	return &this
}

// NewStagingBufferSpecWithDefaults instantiates a new StagingBufferSpec object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStagingBufferSpecWithDefaults() *StagingBufferSpec {
	this := StagingBufferSpec{}
	return &this
}

// GetContact returns the Contact field value if set, zero value otherwise.
func (o *StagingBufferSpec) GetContact() string {
	if o == nil || o.Contact == nil {
		var ret string
		return ret
	}
	return *o.Contact
}

// GetContactOk returns a tuple with the Contact field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StagingBufferSpec) GetContactOk() (*string, bool) {
	if o == nil || o.Contact == nil {
		return nil, false
	}
	return o.Contact, true
}

// HasContact returns a boolean if a field has been set.
func (o *StagingBufferSpec) HasContact() bool {
	if o != nil && o.Contact != nil {
		return true
	}

	return false
}

// SetContact gets a reference to the given string and assigns it to the Contact field.
func (o *StagingBufferSpec) SetContact(v string) {
	o.Contact = &v
}

func (o StagingBufferSpec) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Contact != nil {
		toSerialize["Contact"] = o.Contact
	}
	return json.Marshal(toSerialize)
}

type NullableStagingBufferSpec struct {
	value *StagingBufferSpec
	isSet bool
}

func (v NullableStagingBufferSpec) Get() *StagingBufferSpec {
	return v.value
}

func (v *NullableStagingBufferSpec) Set(val *StagingBufferSpec) {
	v.value = val
	v.isSet = true
}

func (v NullableStagingBufferSpec) IsSet() bool {
	return v.isSet
}

func (v *NullableStagingBufferSpec) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStagingBufferSpec(val *StagingBufferSpec) *NullableStagingBufferSpec {
	return &NullableStagingBufferSpec{value: val, isSet: true}
}

func (v NullableStagingBufferSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStagingBufferSpec) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

