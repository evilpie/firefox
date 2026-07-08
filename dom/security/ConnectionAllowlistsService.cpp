/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ConnectionAllowlistsService.h"

namespace mozilla::dom {

NS_IMPL_ISUPPORTS(ConnectionAllowlistsService, nsIContentPolicy)

NS_IMETHODIMP
ConnectionAllowlistsService::ShouldLoad(nsIURI* aContentLocation,
                                        nsILoadInfo* aLoadInfo,
                                        int16_t* aDecision) {
  *aDecision = nsIContentPolicy::ACCEPT;

  nsCOMPtr<nsIPolicyContainer> policyContainer =
      aLoadInfo->GetPolicyContainer();
  RefPtr<ConnectionAllowlists> allowlists =
      PolicyContainer::GetConnectionAllowlists(policyContainer);
  if (!allowlists) {
    return NS_OK;
  }

  if (allowlists->ShouldLoadBeBlocked(aContentLocation, aLoadInfo)) {
    *aDecision = nsIContentPolicy::REJECT_REQUEST;
  }

  return NS_OK;
}

NS_IMETHODIMP
ConnectionAllowlistsService::ShouldProcess(nsIURI* aContentLocation,
                                           nsILoadInfo* aLoadInfo,
                                           int16_t* aDecision) {
  *aDecision = nsIContentPolicy::ACCEPT;
  return NS_OK;
}

}  // namespace mozilla::dom
