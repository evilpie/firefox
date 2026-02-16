/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WAICTUtils.h"

#include "mozilla/net/SFVService.h"
#include "nsCOMPtr.h"
#include "nsString.h"

namespace mozilla::waict {

nsresult ParseManifest(nsISFVDictionary* aDict, nsACString& outManifest) {
  nsCOMPtr<nsISFVItemOrInnerList> manifest;
  MOZ_TRY(aDict->Get("manifest"_ns, getter_AddRefs(manifest)));

  if (nsCOMPtr<nsISFVItem> manifestItem = do_QueryInterface(manifest)) {
    nsCOMPtr<nsISFVBareItem> value;
    MOZ_TRY(manifestItem->GetValue(getter_AddRefs(value)));

    if (nsCOMPtr<nsISFVString> stringVal = do_QueryInterface(value)) {
      MOZ_TRY(stringVal->GetValue(outManifest));
      if (!outManifest.IsEmpty()) {
        return NS_OK;
      }
    }
  }

  return NS_ERROR_FAILURE;
}

nsresult ParseMaxAge(nsISFVDictionary* aDict, uint64_t* outMaxAge) {
  nsCOMPtr<nsISFVItemOrInnerList> maxAge;
  MOZ_TRY(aDict->Get("max-age"_ns, getter_AddRefs(maxAge)));

  if (nsCOMPtr<nsISFVItem> maxAgeItem = do_QueryInterface(maxAge)) {
    nsCOMPtr<nsISFVBareItem> maxAgeValue;
    MOZ_TRY(maxAgeItem->GetValue(getter_AddRefs(maxAgeValue)));

    if (nsCOMPtr<nsISFVInteger> intVal = do_QueryInterface(maxAgeValue)) {
      int64_t maxAgeSeconds;
      MOZ_TRY(intVal->GetValue(&maxAgeSeconds));
      if (maxAgeSeconds >= 0) {
        *outMaxAge = maxAgeSeconds;
        return NS_OK;
      }
    }
  }

  return NS_ERROR_FAILURE;
}

nsresult ParseMode(nsISFVDictionary* aDict, bool* outEnforce) {
  nsCOMPtr<nsISFVItemOrInnerList> mode;
  MOZ_TRY(aDict->Get("mode"_ns, getter_AddRefs(mode)));

  if (nsCOMPtr<nsISFVItem> modeItem = do_QueryInterface(mode)) {
    nsCOMPtr<nsISFVBareItem> modeValue;
    MOZ_TRY(modeItem->GetValue(getter_AddRefs(modeValue)));

    if (nsCOMPtr<nsISFVToken> tokenVal = do_QueryInterface(modeValue)) {
      nsAutoCString token;
      MOZ_TRY(tokenVal->GetValue(token));

      if (token.EqualsLiteral("enforce")) {
        *outEnforce = true;
        return NS_OK;
      }
      if (token.EqualsLiteral("report")) {
        *outEnforce = false;
        return NS_OK;
      }
    }
  }

  return NS_ERROR_FAILURE;
}

}  // namespace mozilla::waict
