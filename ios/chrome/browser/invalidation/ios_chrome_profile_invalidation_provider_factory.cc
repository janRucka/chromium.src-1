// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ios/chrome/browser/invalidation/ios_chrome_profile_invalidation_provider_factory.h"

#include <utility>

#include "base/callback.h"
#include "base/memory/scoped_ptr.h"
#include "base/memory/singleton.h"
#include "base/prefs/pref_registry.h"
#include "components/gcm_driver/gcm_profile_service.h"
#include "components/invalidation/impl/invalidator_storage.h"
#include "components/invalidation/impl/profile_invalidation_provider.h"
#include "components/invalidation/impl/ticl_invalidation_service.h"
#include "components/invalidation/impl/ticl_profile_settings_provider.h"
#include "components/keyed_service/ios/browser_state_dependency_manager.h"
#include "components/pref_registry/pref_registry_syncable.h"
#include "components/signin/core/browser/profile_identity_provider.h"
#include "components/signin/core/browser/signin_manager.h"
#include "ios/chrome/browser/services/gcm/ios_chrome_gcm_profile_service_factory.h"
#include "ios/chrome/browser/signin/oauth2_token_service_factory.h"
#include "ios/chrome/browser/signin/signin_manager_factory.h"
#include "ios/public/provider/chrome/browser/browser_state/chrome_browser_state.h"
#include "ios/web/public/web_client.h"
#include "net/url_request/url_request_context_getter.h"

using invalidation::InvalidatorStorage;
using invalidation::ProfileInvalidationProvider;
using invalidation::TiclInvalidationService;

// static
invalidation::ProfileInvalidationProvider*
IOSChromeProfileInvalidationProviderFactory::GetForBrowserState(
    ios::ChromeBrowserState* browser_state) {
  return static_cast<ProfileInvalidationProvider*>(
      GetInstance()->GetServiceForBrowserState(browser_state, true));
}

// static
IOSChromeProfileInvalidationProviderFactory*
IOSChromeProfileInvalidationProviderFactory::GetInstance() {
  return base::Singleton<IOSChromeProfileInvalidationProviderFactory>::get();
}

IOSChromeProfileInvalidationProviderFactory::
    IOSChromeProfileInvalidationProviderFactory()
    : BrowserStateKeyedServiceFactory(
          "InvalidationService",
          BrowserStateDependencyManager::GetInstance()) {
  DependsOn(ios::SigninManagerFactory::GetInstance());
  DependsOn(IOSChromeGCMProfileServiceFactory::GetInstance());
  DependsOn(OAuth2TokenServiceFactory::GetInstance());
}

IOSChromeProfileInvalidationProviderFactory::
    ~IOSChromeProfileInvalidationProviderFactory() {}

scoped_ptr<KeyedService>
IOSChromeProfileInvalidationProviderFactory::BuildServiceInstanceFor(
    web::BrowserState* context) const {
  ios::ChromeBrowserState* browser_state =
      ios::ChromeBrowserState::FromBrowserState(context);

  scoped_ptr<IdentityProvider> identity_provider(new ProfileIdentityProvider(
      ios::SigninManagerFactory::GetForBrowserState(browser_state),
      OAuth2TokenServiceFactory::GetForBrowserState(browser_state),
      // LoginUIServiceFactory is not built on iOS.
      base::Closure()));

  scoped_ptr<TiclInvalidationService> service(new TiclInvalidationService(
      web::GetWebClient()->GetUserAgent(false), std::move(identity_provider),
      make_scoped_ptr(new invalidation::TiclProfileSettingsProvider(
          browser_state->GetPrefs())),
      IOSChromeGCMProfileServiceFactory::GetForBrowserState(browser_state)
          ->driver(),
      browser_state->GetRequestContext()));
  service->Init(
      make_scoped_ptr(new InvalidatorStorage(browser_state->GetPrefs())));

  return make_scoped_ptr(new ProfileInvalidationProvider(std::move(service)));
}

void IOSChromeProfileInvalidationProviderFactory::RegisterBrowserStatePrefs(
    user_prefs::PrefRegistrySyncable* registry) {
  ProfileInvalidationProvider::RegisterProfilePrefs(registry);
  InvalidatorStorage::RegisterProfilePrefs(registry);
}
