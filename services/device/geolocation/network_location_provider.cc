// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/device/geolocation/network_location_provider.h"

#include <utility>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/json/json_file_value_serializer.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "chrome/common/chrome_paths_internal.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/device/public/cpp/geolocation/geoposition.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "net/base/network_interfaces.h"

namespace device {
namespace {
// The maximum period of time we'll wait for a complete set of wifi data
// before sending the request.
const int kDataCompleteWaitSeconds = 2;

std::string GetIpForCache() {
  net::NetworkInterfaceList networks;
  net::GetNetworkList(&networks, net::INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES);

  std::string ip;
  for (const net::NetworkInterface& network : networks)
    ip += network.address.ToString();

  return ip;
}

// The maximum age of a cached network location estimate before it can no longer
// be returned as a fresh estimate. This should be at least as long as the
// longest polling interval used by the WifiDataProvider.
const int kLastPositionMaxAgeSeconds = 10 * 60;  // 10 minutes
}  // namespace

// static
const size_t NetworkLocationProvider::PositionCache::kMaximumSize = 200;
const base::TimeDelta NetworkLocationProvider::PositionCache::kCacheExpiration = base::TimeDelta::FromDays(7);

NetworkLocationProvider::PositionCache::PositionCache() {
  base::ThreadRestrictions::SetIOAllowed(true);
#if !defined(COMPONENT_BUILD)
  base::FilePath path;
  if (chrome::GetDefaultUserDataDirectory(&path)) {
    path = path.AppendASCII("geolocationCache");
    if (base::PathExists(path)) {
      std::string error;
      JSONFileValueDeserializer serializer(path);
      std::unique_ptr<base::Value> root(serializer.Deserialize(NULL, &error));
      if (!root.get())
        return;

      std::unique_ptr<base::ListValue> geolocations = base::ListValue::From(std::move(root));
      if (!geolocations)
        return;

      for (size_t i = 0; i < geolocations->GetSize(); i++) {
        base::DictionaryValue* geolocation = nullptr;
        geolocations->GetDictionary(i, &geolocation);
        if (!geolocation)
          continue;

        mojom::Geoposition geo;
        base::string16 macAddress;
        if (!geolocation->GetString("macAddress", &macAddress)
         || !geolocation->GetDouble("latitude", &geo.latitude)
         || !geolocation->GetDouble("longitude", &geo.longitude)
         || !geolocation->GetDouble("altitude", &geo.altitude)
         || !geolocation->GetDouble("accuracy", &geo.accuracy)
         || !geolocation->GetDouble("altitude_accuracy", &geo.altitude_accuracy)
         || !geolocation->GetDouble("heading", &geo.heading)
         || !geolocation->GetDouble("speed", &geo.speed))
          continue;

        double time;
        if (!geolocation->GetDouble("time", &time))
          continue;
        geo.timestamp = base::Time::FromDoubleT(time);

        cache_.insert(std::make_pair(macAddress, geo));
      }
      CacheChecker();
    }
  }
#endif
}

NetworkLocationProvider::PositionCache::~PositionCache() {
  base::ThreadRestrictions::SetIOAllowed(true);
#if !defined(COMPONENT_BUILD)
  base::FilePath path;
  if (chrome::GetDefaultUserDataDirectory(&path)) {
    std::unique_ptr<base::ListValue> geolocations(new base::ListValue());
    for (const std::pair<base::string16, mojom::Geoposition>& cache : cache_) {
      base::DictionaryValue* dict = new base::DictionaryValue;
      dict->SetString("macAddress", cache.first);
      dict->SetDouble("latitude", cache.second.latitude);
      dict->SetDouble("longitude", cache.second.longitude);
      dict->SetDouble("altitude", cache.second.altitude);
      dict->SetDouble("accuracy", cache.second.accuracy);
      dict->SetDouble("altitude_accuracy", cache.second.altitude_accuracy);
      dict->SetDouble("heading", cache.second.heading);
      dict->SetDouble("speed", cache.second.speed);
      dict->SetDouble("time", cache.second.timestamp.ToDoubleT());
      geolocations->Append(std::unique_ptr<base::Value>(static_cast<base::Value*>(dict)));
    }

    JSONFileValueSerializer serializer(path.AppendASCII("geolocationCache"));
    serializer.Serialize(*geolocations);
  }
#endif
}

void NetworkLocationProvider::PositionCache::CacheChecker() {
  for (std::map<base::string16, mojom::Geoposition>::iterator it = cache_.begin(); it != cache_.end();) {
    if (it->second.timestamp < base::Time::Now() - kCacheExpiration)
      cache_.erase(it++);
    else
      ++it;
  }

  if (cache_.size() == kMaximumSize) {
    std::map<base::string16, mojom::Geoposition>::const_iterator oldest = cache_.begin();
    for (std::map<base::string16, mojom::Geoposition>::const_iterator it =
        std::next(cache_.begin(), 1);
        it != cache_.end(); ++it) {
      if (oldest->second.timestamp > it->second.timestamp)
        oldest = it;
    }
    cache_.erase(oldest);
  }
}

bool NetworkLocationProvider::PositionCache::CachePosition(
  const WifiData& wifi_data,
  const mojom::Geoposition& position) {
  for (const auto& access_point_data : wifi_data.access_point_data)
    cache_.insert(make_pair(access_point_data.mac_address, position));

  if (wifi_data.access_point_data.size() == 0)
    cache_.insert(make_pair(base::UTF8ToUTF16(GetIpForCache()), position));

  CacheChecker();
  return true;
}

// Searches for a cached position response for the current WiFi data. Returns
// the cached position if available, nullptr otherwise.
const mojom::Geoposition* NetworkLocationProvider::PositionCache::FindPosition(
  const WifiData& wifi_data) {

  CacheChecker();
  for (const auto& access_point_data : wifi_data.access_point_data) {
    std::map<base::string16, mojom::Geoposition>::const_iterator it = cache_.find(access_point_data.mac_address);
    if (it != cache_.end())
      return &it->second;
  }

  if (wifi_data.access_point_data.size() == 0) {
    std::map<base::string16, mojom::Geoposition>::const_iterator it = cache_.find(base::UTF8ToUTF16(GetIpForCache()));
    if (it != cache_.end())
      return &it->second;
  }

  return nullptr;
}

// NetworkLocationProvider
NetworkLocationProvider::NetworkLocationProvider(
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
    const std::string& api_key,
    LastPositionCache* last_position_cache)
    : wifi_data_provider_manager_(nullptr),
      wifi_data_update_callback_(
          base::Bind(&NetworkLocationProvider::OnWifiDataUpdate,
                     base::Unretained(this))),
      is_wifi_data_complete_(false),
      last_position_delegate_(last_position_cache),
      is_permission_granted_(false),
      is_new_data_available_(false),
      request_(new NetworkLocationRequest(
          std::move(url_loader_factory),
          api_key,
          base::Bind(&NetworkLocationProvider::OnLocationResponse,
                     base::Unretained(this)))),
      position_cache_(new PositionCache),
      weak_factory_(this) {
  DCHECK(last_position_delegate_);
}

NetworkLocationProvider::~NetworkLocationProvider() {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (IsStarted())
    StopProvider();
}

void NetworkLocationProvider::SetUpdateCallback(
    const LocationProvider::LocationProviderUpdateCallback& callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  location_provider_update_callback_ = callback;
}

void NetworkLocationProvider::OnPermissionGranted() {
  const bool was_permission_granted = is_permission_granted_;
  is_permission_granted_ = true;
  if (!was_permission_granted && IsStarted())
    RequestPosition();
}

void NetworkLocationProvider::OnWifiDataUpdate() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(IsStarted());
  is_wifi_data_complete_ = wifi_data_provider_manager_->GetData(&wifi_data_);
  if (is_wifi_data_complete_) {
    wifi_timestamp_ = base::Time::Now();
    is_new_data_available_ = true;
  }

  // When RequestPosition is called, the most recent wifi data is sent to the
  // geolocation service. If the wifi data is incomplete but a cached estimate
  // is available, the cached estimate may be returned instead.
  //
  // If no wifi data is available or the data is incomplete, it may mean the
  // provider is still performing the wifi scan. In this case we should wait
  // for the scan to complete rather than return cached data.
  //
  // A lack of wifi data may also mean the scan is delayed due to the wifi
  // scanning policy. This delay can vary based on how frequently the wifi
  // data changes, but is on the order of a few seconds to several minutes.
  // In this case it is better to call RequestPosition and return a cached
  // position estimate if it is available.
  bool delayed = wifi_data_provider_manager_->DelayedByPolicy();
  if (is_wifi_data_complete_ || delayed)
    RequestPosition();
}

void NetworkLocationProvider::OnLocationResponse(
    const mojom::Geoposition& position,
    bool server_error,
    const WifiData& wifi_data) {
  DCHECK(thread_checker_.CalledOnValidThread());
  // Record the position and update our cache.
  last_position_delegate_->SetLastNetworkPosition(position);
  if (ValidateGeoposition(position))
    position_cache_->CachePosition(wifi_data, position);

  // Let listeners know that we now have a position available.
  if (!location_provider_update_callback_.is_null()) {
    location_provider_update_callback_.Run(
        this, last_position_delegate_->GetLastNetworkPosition());
  }
}

void NetworkLocationProvider::StartProvider(bool high_accuracy) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (IsStarted())
    return;

  // Registers a callback with the data provider. The first call to Register()
  // will create a singleton data provider that will be deleted on Unregister().
  wifi_data_provider_manager_ =
      WifiDataProviderManager::Register(&wifi_data_update_callback_);

  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&NetworkLocationProvider::RequestPosition,
                     weak_factory_.GetWeakPtr()),
      base::TimeDelta::FromSeconds(kDataCompleteWaitSeconds));

  OnWifiDataUpdate();
}

void NetworkLocationProvider::StopProvider() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(IsStarted());
  wifi_data_provider_manager_->Unregister(&wifi_data_update_callback_);
  wifi_data_provider_manager_ = nullptr;
  weak_factory_.InvalidateWeakPtrs();
}

const mojom::Geoposition& NetworkLocationProvider::GetPosition() {
  return last_position_delegate_->GetLastNetworkPosition();
}

void NetworkLocationProvider::RequestPosition() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // The wifi polling policy may require us to wait for several minutes before
  // fresh wifi data is available. To ensure we can return a position estimate
  // quickly when the network location provider is the primary provider, allow
  // a cached value to be returned under certain conditions.
  //
  // If we have a sufficiently recent network location estimate and we do not
  // expect to receive a new one soon (i.e., no new wifi data is available and
  // there is no pending network request), report the last network position
  // estimate as if it were a fresh estimate.
  const mojom::Geoposition& last_position =
      last_position_delegate_->GetLastNetworkPosition();
  if (!is_new_data_available_ && !request_->is_request_pending() &&
      ValidateGeoposition(last_position)) {
    base::Time now = base::Time::Now();
    base::TimeDelta last_position_age = now - last_position.timestamp;
    if (last_position_age.InSeconds() < kLastPositionMaxAgeSeconds &&
        !location_provider_update_callback_.is_null()) {
      // Update the timestamp to the current time.
      mojom::Geoposition position = last_position;
      position.timestamp = now;
      location_provider_update_callback_.Run(this, position);
    }
  }

  if (!is_new_data_available_ || !is_wifi_data_complete_)
    return;
  DCHECK(!wifi_timestamp_.is_null())
      << "|wifi_timestamp_| must be set before looking up position";

  const mojom::Geoposition* cached_position =
      position_cache_->FindPosition(wifi_data_);
  if (cached_position) {
    mojom::Geoposition position(*cached_position);
    DCHECK(ValidateGeoposition(position));
    // The timestamp of a position fix is determined by the timestamp
    // of the source data update. (The value of position.timestamp from
    // the cache could be from weeks ago!)
    position.timestamp = wifi_timestamp_;
    is_new_data_available_ = false;

    // Record the position.
    last_position_delegate_->SetLastNetworkPosition(position);

    // Let listeners know that we now have a position available.
    if (!location_provider_update_callback_.is_null())
      location_provider_update_callback_.Run(this, position);
    return;
  }
  // Don't send network requests until authorized. http://crbug.com/39171
  if (!is_permission_granted_)
    return;

  is_new_data_available_ = false;

  // TODO(joth): Rather than cancel pending requests, we should create a new
  // NetworkLocationRequest for each and hold a set of pending requests.
  DLOG_IF(WARNING, request_->is_request_pending())
      << "NetworkLocationProvider - pre-empting pending network request "
         "with new data. Wifi APs: "
      << wifi_data_.access_point_data.size();

  net::PartialNetworkTrafficAnnotationTag partial_traffic_annotation =
      net::DefinePartialNetworkTrafficAnnotation("network_location_provider",
                                                 "network_location_request",
                                                 R"(
      semantics {
        sender: "Network Location Provider"
      }
      policy {
        setting:
          "Users can control this feature via the Location setting under "
          "'Privacy', 'Content Settings', 'Location'."
        chrome_policy {
          DefaultGeolocationSetting {
            DefaultGeolocationSetting: 2
          }
        }
      })");
  request_->MakeRequest(wifi_data_, wifi_timestamp_,
                        partial_traffic_annotation);
}

bool NetworkLocationProvider::IsStarted() const {
  return wifi_data_provider_manager_ != nullptr;
}

}  // namespace device
