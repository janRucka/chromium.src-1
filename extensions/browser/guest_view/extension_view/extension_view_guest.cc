// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "extensions/browser/guest_view/extension_view/extension_view_guest.h"

#include <utility>

#include "components/crx_file/id_util.h"
#include "components/guest_view/browser/guest_view_event.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/common/result_codes.h"
#include "extensions/browser/api/extensions_api_client.h"
#include "extensions/browser/bad_message.h"
#include "extensions/browser/guest_view/extension_view/extension_view_constants.h"
#include "extensions/browser/guest_view/extension_view/whitelist/extension_view_whitelist.h"
#include "extensions/common/constants.h"
#include "extensions/common/extension_messages.h"
#include "extensions/strings/grit/extensions_strings.h"

using content::WebContents;
using guest_view::GuestViewBase;
using guest_view::GuestViewEvent;
using namespace extensions::api;

namespace extensions {

// static
const char ExtensionViewGuest::Type[] = "extensionview";

ExtensionViewGuest::ExtensionViewGuest(WebContents* owner_web_contents)
    : GuestView<ExtensionViewGuest>(owner_web_contents) {}

ExtensionViewGuest::~ExtensionViewGuest() {
}

// static
GuestViewBase* ExtensionViewGuest::Create(WebContents* owner_web_contents) {
  return new ExtensionViewGuest(owner_web_contents);
}

bool ExtensionViewGuest::NavigateGuest(const std::string& src,
                                       bool force_navigation) {
  GURL url = extension_url_.Resolve(src);

  // If the URL is not valid, about:blank, or the same origin as the extension,
  // then navigate to about:blank.
  bool url_not_allowed = (url != GURL(url::kAboutBlankURL)) &&
      (url.GetOrigin() != extension_url_.GetOrigin());
  if (!url.is_valid() || url_not_allowed)
    return NavigateGuest(url::kAboutBlankURL, true /* force_navigation */);

  if (!force_navigation && (url_ == url))
    return false;

  web_contents()->GetRenderProcessHost()->FilterURL(false, &url);
  web_contents()->GetController().LoadURL(url, content::Referrer(),
                                          ui::PAGE_TRANSITION_AUTO_TOPLEVEL,
                                          std::string());

  url_ = url;
  return true;
}

// GuestViewBase implementation.
bool ExtensionViewGuest::CanRunInDetachedState() const {
  return true;
}

void ExtensionViewGuest::CreateWebContents(
    const base::DictionaryValue& create_params,
    const WebContentsCreatedCallback& callback) {
  // Gets the extension ID.
  std::string extension_id;
  create_params.GetString(extensionview::kAttributeExtension, &extension_id);

  if (!crx_file::id_util::IdIsValid(extension_id) ||
      !IsExtensionIdWhitelisted(extension_id)) {
    callback.Run(nullptr);
    return;
  }

  // Gets the extension URL.
  extension_url_ =
      extensions::Extension::GetBaseURLFromExtensionId(extension_id);

  if (!extension_url_.is_valid()) {
    callback.Run(nullptr);
    return;
  }

  content::SiteInstance* view_site_instance =
      content::SiteInstance::CreateForURL(browser_context(),
                                          extension_url_);

  WebContents::CreateParams params(browser_context(), view_site_instance);
  params.guest_delegate = this;
  callback.Run(WebContents::Create(params));
}

void ExtensionViewGuest::DidInitialize(
    const base::DictionaryValue& create_params) {
  ExtensionsAPIClient::Get()->AttachWebContentsHelpers(web_contents());

  ApplyAttributes(create_params);
}

void ExtensionViewGuest::DidAttachToEmbedder() {
  ApplyAttributes(*attach_params());
}

const char* ExtensionViewGuest::GetAPINamespace() const {
  return extensionview::kAPINamespace;
}

int ExtensionViewGuest::GetTaskPrefix() const {
  return IDS_EXTENSION_TASK_MANAGER_EXTENSIONVIEW_TAG_PREFIX;
}

void ExtensionViewGuest::DidCommitProvisionalLoadForFrame(
    content::RenderFrameHost* render_frame_host,
    const GURL& url,
    ui::PageTransition transition_type) {
  if (render_frame_host->GetParent())
    return;

  url_ = url;

  scoped_ptr<base::DictionaryValue> args(new base::DictionaryValue());
  args->SetString(guest_view::kUrl, url_.spec());
  DispatchEventToView(
      new GuestViewEvent(extensionview::kEventLoadCommit, std::move(args)));
}

void ExtensionViewGuest::DidNavigateMainFrame(
    const content::LoadCommittedDetails& details,
    const content::FrameNavigateParams& params) {
  if (attached() && (params.url.GetOrigin() != url_.GetOrigin())) {
    bad_message::ReceivedBadMessage(web_contents()->GetRenderProcessHost(),
                                    bad_message::EVG_BAD_ORIGIN);
  }
}

void ExtensionViewGuest::ApplyAttributes(const base::DictionaryValue& params) {
  std::string src;
  params.GetString(extensionview::kAttributeSrc, &src);
  NavigateGuest(src, false /* force_navigation */);
}

}  // namespace extensions
