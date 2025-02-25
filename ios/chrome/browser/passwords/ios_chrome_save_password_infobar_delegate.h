// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IOS_CHROME_BROWSER_PASSWORDS_IOS_CHROME_SAVE_PASSWORD_INFOBAR_DELEGATE_H_
#define IOS_CHROME_BROWSER_PASSWORDS_IOS_CHROME_SAVE_PASSWORD_INFOBAR_DELEGATE_H_

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "components/infobars/core/confirm_infobar_delegate.h"

namespace password_manager {
class PasswordFormManager;
}

namespace infobars {
class InfoBarManager;
}

// After a successful *new* login attempt, Chrome passes the current
// password_manager::PasswordFormManager and move it to a
// IOSChromeSavePasswordInfoBarDelegate while the user makes up their mind
// with the "save password" infobar.
class IOSChromeSavePasswordInfoBarDelegate : public ConfirmInfoBarDelegate {
 public:
  // Creates the infobar for |form_to_save| and adds it to |infobar_manager|.
  // |is_smart_lock_enabled| controls the branding string.
  static void Create(
      bool is_smart_lock_branding_enabled,
      infobars::InfoBarManager* infobar_manager,
      scoped_ptr<password_manager::PasswordFormManager> form_to_save);

  ~IOSChromeSavePasswordInfoBarDelegate() override;

 private:
  enum ResponseType {
    NO_RESPONSE = 0,
    REMEMBER_PASSWORD,
    DO_NOT_REMEMBER_PASSWORD,
    NUM_RESPONSE_TYPES,
  };

  IOSChromeSavePasswordInfoBarDelegate(
      bool is_smart_lock_branding_enabled,
      scoped_ptr<password_manager::PasswordFormManager> form_to_save);

  // ConfirmInfoBarDelegate implementation.
  Type GetInfoBarType() const override;
  infobars::InfoBarDelegate::InfoBarIdentifier GetIdentifier() const override;
  base::string16 GetMessageText() const override;
  base::string16 GetLinkText() const override;
  base::string16 GetButtonLabel(InfoBarButton button) const override;
  bool Accept() override;
  bool Cancel() override;
  int GetIconId() const override;
  bool LinkClicked(WindowOpenDisposition disposition) override;

  // The password_manager::PasswordFormManager managing the form we're asking
  // the user about, and should update as per her decision.
  scoped_ptr<password_manager::PasswordFormManager> form_to_save_;

  // Used to track the results we get from the info bar.
  ResponseType infobar_response_;

  // Whether to show the password manager branded as Smart Lock.
  bool is_smart_lock_branding_enabled_;

  DISALLOW_COPY_AND_ASSIGN(IOSChromeSavePasswordInfoBarDelegate);
};

#endif  // IOS_CHROME_BROWSER_PASSWORDS_IOS_CHROME_SAVE_PASSWORD_INFOBAR_DELEGATE_H_
