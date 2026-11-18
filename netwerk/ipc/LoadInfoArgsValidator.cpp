/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/net/LoadInfoArgsValidator.h"

#include "mozilla/dom/ClientValidation.h"
#include "mozilla/dom/LoadedOriginSet.h"
#include "nsIPrincipal.h"

namespace mozilla::net {

using dom::ValidatePrincipalOptions;

namespace {

bool IsNullOrContentPrincipal(nsIPrincipal* aPrincipal) {
  return !aPrincipal || aPrincipal->GetIsContentPrincipal() ||
         aPrincipal->GetIsNullPrincipal();
}

bool IsValidTriggeringPrincipal(
    dom::LoadedOriginSet* aLoadedOrigins, nsIPrincipal* aPrincipal,
    EnumSet<ValidatePrincipalOptions> aOptions = {}) {
  // Extension content scripts trigger loads with expanded principals.
  aOptions += {ValidatePrincipalOptions::AllowExpanded,
               ValidatePrincipalOptions::AllowSystemIfLoaded};
  return aLoadedOrigins->ValidatePrincipal(aPrincipal, aOptions);
}

bool ValidateClientInfoFromContent(dom::LoadedOriginSet* aLoadedOrigins,
                                   const dom::IPCClientInfo& aClientInfo) {
  return dom::ClientIsValidPrincipalInfo(aClientInfo.principalInfo(),
                                         aLoadedOrigins);
}

// Redirects may go to any origin, so the principal doesn't need to be loaded
// in the content process.
class ContentRedirectHistoryEntryInfoValidator final
    : public RedirectHistoryEntryInfoValidator {
 public:
  bool ValidatePrincipal(NotNull<nsIPrincipal*> aPrincipal) override {
    return IsNullOrContentPrincipal(aPrincipal);
  }
};

bool ValidateRedirectFromContent(
    Tainted<const RedirectHistoryEntryInfo&> aEntry) {
  ContentRedirectHistoryEntryInfoValidator validator;
  return ValidateTaintedFields(aEntry, validator);
}

class ContentInterceptionInfoArgValidator final
    : public InterceptionInfoArgValidator {
 public:
  explicit ContentInterceptionInfoArgValidator(
      dom::LoadedOriginSet* aLoadedOrigins)
      : mLoadedOrigins(aLoadedOrigins) {}

  bool ValidateTriggeringPrincipal(NotNull<nsIPrincipal*> aPrincipal) override {
    return IsValidTriggeringPrincipal(mLoadedOrigins, aPrincipal);
  }

  bool ValidateRedirectChain(
      Tainted<const RedirectHistoryEntryInfo&> aEntry) override {
    return ValidateRedirectFromContent(aEntry);
  }

 private:
  dom::LoadedOriginSet* mLoadedOrigins;
};

class ContentLoadInfoArgsValidator final : public LoadInfoArgsValidator {
 public:
  explicit ContentLoadInfoArgsValidator(dom::LoadedOriginSet* aLoadedOrigins)
      : mLoadedOrigins(aLoadedOrigins) {}

  // Principals of documents in the content process.
  bool ValidateRequestingPrincipal(nsIPrincipal* aPrincipal) override {
    return mLoadedOrigins->ValidatePrincipal(
        aPrincipal, {ValidatePrincipalOptions::AllowNullPtr,
                     ValidatePrincipalOptions::AllowSystemIfLoaded});
  }

  bool ValidateTriggeringPrincipal(nsIPrincipal* aPrincipal) override {
    return IsValidTriggeringPrincipal(mLoadedOrigins, aPrincipal,
                                      {ValidatePrincipalOptions::AllowNullPtr});
  }

  bool ValidatePrincipalToInherit(nsIPrincipal* aPrincipal) override {
    return mLoadedOrigins->ValidatePrincipal(
        aPrincipal, {ValidatePrincipalOptions::AllowNullPtr,
                     ValidatePrincipalOptions::AllowSystemIfLoaded});
  }

  bool ValidateClientInfo(const dom::IPCClientInfo& aClientInfo) override {
    return ValidateClientInfoFromContent(mLoadedOrigins, aClientInfo);
  }

  bool ValidateInitialClientInfo(
      const dom::IPCClientInfo& aClientInfo) override {
    return ValidateClientInfoFromContent(mLoadedOrigins, aClientInfo);
  }

  // Principals which may belong to documents in other processes.
  bool ValidateTopLevelPrincipal(nsIPrincipal* aPrincipal) override {
    return IsNullOrContentPrincipal(aPrincipal);
  }

  bool ValidateAncestorOrigins(nsIPrincipal* aPrincipal) override {
    return IsNullOrContentPrincipal(aPrincipal);
  }

  // The client of a document which doesn't exist yet, so its origin may not
  // have been loaded in the content process.
  bool ValidateReservedClientInfo(
      const dom::IPCClientInfo& aClientInfo) override {
    return ValidateClientInfoFromContent(nullptr, aClientInfo);
  }

  bool ValidateRedirectChain(
      Tainted<const RedirectHistoryEntryInfo&> aEntry) override {
    return ValidateRedirectFromContent(aEntry);
  }

  bool ValidateRedirectChainIncludingInternalRedirects(
      Tainted<const RedirectHistoryEntryInfo&> aEntry) override {
    return ValidateRedirectFromContent(aEntry);
  }

  bool ValidateInterceptionInfo(
      Tainted<const InterceptionInfoArg&> aInterceptionInfo) override {
    ContentInterceptionInfoArgValidator validator(mLoadedOrigins);
    return ValidateTaintedFields(aInterceptionInfo, validator);
  }

 private:
  dom::LoadedOriginSet* mLoadedOrigins;
};

}  // namespace

Maybe<LoadInfoArgs> ValidateLoadInfoArgsFromContent(
    Tainted<LoadInfoArgs>&& aArgs, dom::LoadedOriginSet* aLoadedOrigins) {
  ContentLoadInfoArgsValidator validator(aLoadedOrigins);
  return ValidateTaintedFields(std::move(aArgs), validator);
}

}  // namespace mozilla::net
