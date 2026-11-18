/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/net/LoadInfoArgsValidator.h"

#include "mozilla/dom/ClientValidation.h"
#include "mozilla/dom/LoadedOriginSet.h"
#include "nsIPrincipal.h"

namespace mozilla::net {

using dom::ValidatePrincipalOptions;

static bool IsNullOrContentPrincipal(nsIPrincipal* aPrincipal) {
  return !aPrincipal || aPrincipal->GetIsContentPrincipal() ||
         aPrincipal->GetIsNullPrincipal();
}

bool LoadInfoArgsValidator::ValidateRequestingPrincipal(
    nsIPrincipal* aPrincipal) {
  return mLoadedOrigins->ValidatePrincipal(
      aPrincipal, {ValidatePrincipalOptions::AllowNullPtr,
                   ValidatePrincipalOptions::AllowSystemIfLoaded});
}

static bool ValidateTriggeringPrincipalFromContent(
    dom::LoadedOriginSet* aLoadedOrigins, nsIPrincipal* aPrincipal,
    EnumSet<ValidatePrincipalOptions> aOptions = {}) {
  // Extension content scripts trigger loads with expanded principals.
  aOptions += {ValidatePrincipalOptions::AllowExpanded,
               ValidatePrincipalOptions::AllowSystemIfLoaded};
  return aLoadedOrigins->ValidatePrincipal(aPrincipal, aOptions);
}

bool RedirectHistoryEntryInfoValidator::ValidatePrincipal(
    nsIPrincipal* aPrincipal) {
  return aPrincipal && IsNullOrContentPrincipal(aPrincipal);
}

static_assert(
    ValidatesRedirectHistoryEntryInfo<RedirectHistoryEntryInfoValidator>);

bool InterceptionInfoArgValidator::ValidateTriggeringPrincipal(
    nsIPrincipal* aPrincipal) {
  return ValidateTriggeringPrincipalFromContent(mLoadedOrigins, aPrincipal);
}

static_assert(ValidatesInterceptionInfoArg<InterceptionInfoArgValidator>);

bool LoadInfoArgsValidator::ValidateTriggeringPrincipal(
    nsIPrincipal* aPrincipal) {
  return ValidateTriggeringPrincipalFromContent(
      mLoadedOrigins, aPrincipal, {ValidatePrincipalOptions::AllowNullPtr});
}

bool LoadInfoArgsValidator::ValidatePrincipalToInherit(
    nsIPrincipal* aPrincipal) {
  return mLoadedOrigins->ValidatePrincipal(
      aPrincipal, {ValidatePrincipalOptions::AllowNullPtr,
                   ValidatePrincipalOptions::AllowSystemIfLoaded});
}

bool LoadInfoArgsValidator::ValidateClientInfo(
    const dom::IPCClientInfo& aClientInfo) {
  return dom::ClientIsValidPrincipalInfo(aClientInfo.principalInfo(),
                                         mLoadedOrigins);
}

bool LoadInfoArgsValidator::ValidateTopLevelPrincipal(
    nsIPrincipal* aPrincipal) {
  return IsNullOrContentPrincipal(aPrincipal);
}

bool LoadInfoArgsValidator::ValidateAncestorOrigins(nsIPrincipal* aPrincipal) {
  return IsNullOrContentPrincipal(aPrincipal);
}

bool LoadInfoArgsValidator::ValidateReservedClientInfo(
    const dom::IPCClientInfo& aClientInfo) {
  return dom::ClientIsValidPrincipalInfo(aClientInfo.principalInfo(), nullptr);
}

bool LoadInfoArgsValidator::ValidateInitialClientInfo(
    const dom::IPCClientInfo& aClientInfo) {
  return dom::ClientIsValidPrincipalInfo(aClientInfo.principalInfo(),
                                         mLoadedOrigins);
}

static_assert(ValidatesLoadInfoArgs<LoadInfoArgsValidator>);

Maybe<LoadInfoArgs> ValidateLoadInfoArgsFromContent(
    Tainted<LoadInfoArgs>&& aArgs, dom::LoadedOriginSet* aLoadedOrigins) {
  return ValidateTaintedFields(std::move(aArgs),
                               LoadInfoArgsValidator(aLoadedOrigins));
}

}  // namespace mozilla::net
