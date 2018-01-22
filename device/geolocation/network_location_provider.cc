// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "device/geolocation/network_location_provider.h"

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
#include "net/url_request/url_request_context_getter.h"
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

        Geoposition geo;
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
    for (const std::pair<base::string16, Geoposition>& cache : cache_) {
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
  for (std::map<base::string16, Geoposition>::iterator it = cache_.begin(); it != cache_.end();) {
    if (it->second.timestamp < base::Time::Now() - kCacheExpiration)
      cache_.erase(it++);
    else
      ++it;
  }

  if (cache_.size() == kMaximumSize) {
    std::map<base::string16, Geoposition>::const_iterator oldest = cache_.begin();
    for (std::map<base::string16, Geoposition>::const_iterator it = 
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
  const Geoposition& position) {
  for (const auto& access_point_data : wifi_data.access_point_data)
      cache_.insert(make_pair(access_point_data.mac_address, position));

  if (wifi_data.access_point_data.size() == 0)
      cache_.insert(make_pair(base::UTF8ToUTF16(GetIpForCache()), position));

  CacheChecker();
  return true;
}

// Searches for a cached position response for the current WiFi data. Returns
// the cached position if available, nullptr otherwise.
const Geoposition* NetworkLocationProvider::PositionCache::FindPosition(
    const WifiData& wifi_data) {

  CacheChecker();
  for (const auto& access_point_data : wifi_data.access_point_data) {
    std::map<base::string16, Geoposition>::const_iterator it = cache_.find(access_point_data.mac_address);
    if (it != cache_.end())
      return &it->second;
  }

  if (wifi_data.access_point_data.size() == 0) {
    std::map<base::string16, Geoposition>::const_iterator it = cache_.find(base::UTF8ToUTF16(GetIpForCache()));
    if (it != cache_.end())
      return &it->second;
  }

  return nullptr;
}

// NetworkLocationProvider
NetworkLocationProvider::NetworkLocationProvider(
    scoped_refptr<net::URLRequestContextGetter> url_context_getter,
    const std::string& api_key)
    : wifi_data_provider_manager_(nullptr),
      wifi_data_update_callback_(
          base::Bind(&NetworkLocationProvider::OnWifiDataUpdate,
                     base::Unretained(this))),
      is_wifi_data_complete_(false),
      is_permission_granted_(false),
      is_new_data_available_(false),
      request_(new NetworkLocationRequest(
          std::move(url_context_getter),
          api_key,
          base::Bind(&NetworkLocationProvider::OnLocationResponse,
                     base::Unretained(this)))),
      position_cache_(new PositionCache),
      weak_factory_(this) {}

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
  if (!is_wifi_data_complete_)
    return;

  wifi_timestamp_ = base::Time::Now();
  is_new_data_available_ = true;
  RequestPosition();
}

void NetworkLocationProvider::OnLocationResponse(
    const Geoposition& position,
    bool server_error,
    const WifiData& wifi_data) {
  DCHECK(thread_checker_.CalledOnValidThread());
  // Record the position and update our cache.
  position_ = position;
  if (position.Validate())
    position_cache_->CachePosition(wifi_data, position);

  // Let listeners know that we now have a position available.
  if (!location_provider_update_callback_.is_null())
    location_provider_update_callback_.Run(this, position_);
}

bool NetworkLocationProvider::StartProvider(bool high_accuracy) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (IsStarted())
    return true;

  // Registers a callback with the data provider. The first call to Register()
  // will create a singleton data provider that will be deleted on Unregister().
  wifi_data_provider_manager_ =
      WifiDataProviderManager::Register(&wifi_data_update_callback_);

  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, base::Bind(&NetworkLocationProvider::RequestPosition,
                            weak_factory_.GetWeakPtr()),
      base::TimeDelta::FromSeconds(kDataCompleteWaitSeconds));

  OnWifiDataUpdate();
  return true;
}

void NetworkLocationProvider::StopProvider() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(IsStarted());
  wifi_data_provider_manager_->Unregister(&wifi_data_update_callback_);
  wifi_data_provider_manager_ = nullptr;
  weak_factory_.InvalidateWeakPtrs();
}

const Geoposition& NetworkLocationProvider::GetPosition() {
  return position_;
}

void NetworkLocationProvider::RequestPosition() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!is_new_data_available_ || !is_wifi_data_complete_)
    return;
  DCHECK(!wifi_timestamp_.is_null())
      << "|wifi_timestamp_| must be set before looking up position";

  const Geoposition* cached_position =
      position_cache_->FindPosition(wifi_data_);
  if (cached_position) {
    DCHECK(cached_position->Validate());
    // Record the position and update its timestamp.
    position_ = *cached_position;

    // The timestamp of a position fix is determined by the timestamp
    // of the source data update. (The value of position_.timestamp from
    // the cache could be from weeks ago!)
    position_.timestamp = wifi_timestamp_;
    is_new_data_available_ = false;

    // Let listeners know that we now have a position available.
    if (!location_provider_update_callback_.is_null())
      location_provider_update_callback_.Run(this, position_);
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

  request_->MakeRequest(wifi_data_, wifi_timestamp_);
}

bool NetworkLocationProvider::IsStarted() const {
  return wifi_data_provider_manager_ != nullptr;
}

}  // namespace device
