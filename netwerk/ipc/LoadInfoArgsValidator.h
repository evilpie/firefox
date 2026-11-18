/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_LoadInfoArgsValidator_h
#define mozilla_net_LoadInfoArgsValidator_h

#include "mozilla/Maybe.h"
#include "mozilla/Tainting.h"
#include "mozilla/net/NeckoChannelParams.h"

namespace mozilla::dom {
class LoadedOriginSet;
}

namespace mozilla::net {

/**
 * Validates a RedirectHistoryEntryInfo received from a content process.
 * Redirects may go to any origin, so the principal doesn't need to be loaded
 * in that process.
 */
class RedirectHistoryEntryInfoValidator {
 public:
  bool ValidatePrincipal(nsIPrincipal* aPrincipal);
};

/**
 * Validates an InterceptionInfoArg received from a content process, whose
 * loaded origins are |aLoadedOrigins|.
 */
class InterceptionInfoArgValidator {
 public:
  explicit InterceptionInfoArgValidator(dom::LoadedOriginSet* aLoadedOrigins)
      : mLoadedOrigins(aLoadedOrigins) {}

  bool ValidateTriggeringPrincipal(nsIPrincipal* aPrincipal);
  RedirectHistoryEntryInfoValidator RedirectChain() { return {}; }

 private:
  dom::LoadedOriginSet* mLoadedOrigins;
};

/**
 * Validates a LoadInfoArgs received from a content process, whose loaded
 * origins are |aLoadedOrigins|.
 */
class LoadInfoArgsValidator {
 public:
  explicit LoadInfoArgsValidator(dom::LoadedOriginSet* aLoadedOrigins)
      : mLoadedOrigins(aLoadedOrigins) {}

  // Principals of documents in the content process.
  bool ValidateRequestingPrincipal(nsIPrincipal* aPrincipal);
  bool ValidateTriggeringPrincipal(nsIPrincipal* aPrincipal);
  bool ValidatePrincipalToInherit(nsIPrincipal* aPrincipal);
  bool ValidateClientInfo(const dom::IPCClientInfo& aClientInfo);
  bool ValidateInitialClientInfo(const dom::IPCClientInfo& aClientInfo);

  // Principals which may belong to documents in other processes.
  bool ValidateTopLevelPrincipal(nsIPrincipal* aPrincipal);
  bool ValidateAncestorOrigins(nsIPrincipal* aPrincipal);

  // The client of a document which doesn't exist yet, so its origin may not
  // have been loaded in the content process.
  bool ValidateReservedClientInfo(const dom::IPCClientInfo& aClientInfo);

  RedirectHistoryEntryInfoValidator RedirectChain() { return {}; }
  RedirectHistoryEntryInfoValidator RedirectChainIncludingInternalRedirects() {
    return {};
  }
  InterceptionInfoArgValidator InterceptionInfo() {
    return InterceptionInfoArgValidator(mLoadedOrigins);
  }

 private:
  dom::LoadedOriginSet* mLoadedOrigins;
};

Maybe<LoadInfoArgs> ValidateLoadInfoArgsFromContent(
    Tainted<LoadInfoArgs>&& aArgs, dom::LoadedOriginSet* aLoadedOrigins);

}  // namespace mozilla::net

#endif  // mozilla_net_LoadInfoArgsValidator_h
