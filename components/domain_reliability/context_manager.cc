// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/domain_reliability/context_manager.h"

#include <utility>

namespace domain_reliability {

DomainReliabilityContextManager::DomainReliabilityContextManager(
    DomainReliabilityContext::Factory* context_factory)
    : context_factory_(context_factory) {
}

DomainReliabilityContextManager::~DomainReliabilityContextManager() {
  RemoveAllContexts();
}

void DomainReliabilityContextManager::RouteBeacon(
    scoped_ptr<DomainReliabilityBeacon> beacon) {
  DomainReliabilityContext* context = GetContextForHost(beacon->url.host());
  if (!context)
    return;

  context->OnBeacon(std::move(beacon));
}

void DomainReliabilityContextManager::ClearBeaconsInAllContexts() {
  for (auto& context_entry : contexts_)
    context_entry.second->ClearBeacons();
}

DomainReliabilityContext* DomainReliabilityContextManager::AddContextForConfig(
    scoped_ptr<const DomainReliabilityConfig> config) {
  // TODO(ttuttle): Convert this to actual origin.

  std::string wildcard_prefix = "";
  if (config->include_subdomains)
    wildcard_prefix = "*.";

  std::string domain = wildcard_prefix + config->origin.host();
  scoped_ptr<DomainReliabilityContext> context =
      context_factory_->CreateContextForConfig(std::move(config));
  DomainReliabilityContext** entry = &contexts_[domain];
  if (*entry)
    delete *entry;
  *entry = context.release();
  return *entry;
}

void DomainReliabilityContextManager::RemoveAllContexts() {
  STLDeleteContainerPairSecondPointers(
      contexts_.begin(), contexts_.end());
  contexts_.clear();
}

scoped_ptr<base::Value> DomainReliabilityContextManager::GetWebUIData() const {
  scoped_ptr<base::ListValue> contexts_value(new base::ListValue());
  for (const auto& context_entry : contexts_)
    contexts_value->Append(context_entry.second->GetWebUIData().release());
  return std::move(contexts_value);
}

DomainReliabilityContext* DomainReliabilityContextManager::GetContextForHost(
    const std::string& host) {
  ContextMap::const_iterator context_it;

  context_it = contexts_.find(host);
  if (context_it != contexts_.end())
    return context_it->second;

  std::string host_with_asterisk = "*." + host;
  context_it = contexts_.find(host_with_asterisk);
  if (context_it != contexts_.end())
    return context_it->second;

  size_t dot_pos = host.find('.');
  if (dot_pos == std::string::npos)
    return nullptr;

  // TODO(ttuttle): Make sure parent is not in PSL before using.

  std::string parent_with_asterisk = "*." + host.substr(dot_pos + 1);
  context_it = contexts_.find(parent_with_asterisk);
  if (context_it != contexts_.end())
    return context_it->second;

  return nullptr;
}

}  // namespace domain_reliability
