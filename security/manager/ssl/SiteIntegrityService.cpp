/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "SiteIntegrityService.h"

#include "mozilla/net/SFVService.h"
#include "nsIDataStorage.h"

using namespace mozilla;

NS_IMPL_ISUPPORTS(SiteIntegrityService, nsISiteIntegrityService)

SiteIntegrityService::~SiteIntegrityService() = default;

nsresult SiteIntegrityService::Init() {
  printf("SiteIntegrityService::Init pid=%d\n", getpid());

  nsCOMPtr<nsIDataStorageManager> dataStorageManager(
      do_GetService("@mozilla.org/security/datastoragemanager;1"));
  if (!dataStorageManager) {
    return NS_ERROR_FAILURE;
  }

  MOZ_TRY(
      dataStorageManager->Get(nsIDataStorageManager::SiteIntegrityServiceState,
                              getter_AddRefs(mDataStorage)));

  if (!mDataStorage) {
    return NS_ERROR_FAILURE;
  }

  printf("> ok\n");

  return NS_OK;
}

static nsresult GetHost(nsIURI* aURI, nsACString& outResult) {
  nsCOMPtr<nsIURI> innerURI = NS_GetInnermostURI(aURI);
  if (!innerURI) {
    return NS_ERROR_FAILURE;
  }

  nsAutoCString host;
  nsresult rv = innerURI->GetAsciiHost(host);
  if (NS_FAILED(rv)) {
    return rv;
  }

  outResult.Assign(PublicKeyPinningService::CanonicalizeHostname(host.get()));
  if (outResult.IsEmpty()) {
    return NS_ERROR_UNEXPECTED;
  }

  return NS_OK;
}

static void GetStorageKey(const nsACString& aHostname,
                          const OriginAttributes& aOriginAttributes,
                          nsAutoCString& outStorageKey) {
  outStorageKey = aHostname;

  // Don't isolate by userContextId.
  // ???
  OriginAttributes originAttributesNoUserContext = aOriginAttributes;
  originAttributesNoUserContext.mUserContextId =
      nsIScriptSecurityManager::DEFAULT_USER_CONTEXT_ID;
  // NormalizePartitionKey(originAttributesNoUserContext.mPartitionKey);
  nsAutoCString originAttributesSuffix;
  originAttributesNoUserContext.CreateSuffix(originAttributesSuffix);

  outStorageKey.Append(originAttributesSuffix);

  // XXX for localhost the storageKey inclues https (note the s)???
}

NS_IMETHODIMP
SiteIntegrityService::ProcessHeader(nsIURI* aSourceURI,
                                    const nsACString& aHeader,
                                    const OriginAttributes& aOriginAttributes) {
  ParseHeader(aHeader);

  nsAutoCString host;
  GetHost(aSourceURI, host);

  MOZ_DBG(host);

  nsAutoCString storageKey;
  GetStorageKey(host, aOriginAttributes, storageKey);

  nsIDataStorage::DataType storageType =
      aOriginAttributes.IsPrivateBrowsing()
          ? nsIDataStorage::DataType::Private
          : nsIDataStorage::DataType::Persistent;

  MOZ_DBG(storageKey);

  nsAutoCString value;
  mDataStorage->Get(storageKey, storageType, value);

  MOZ_DBG(value);

  mDataStorage->Put(storageKey, "hello world"_ns, storageType);

  return NS_OK;
}

nsresult SiteIntegrityService::ParseHeader(const nsACString& aHeader) {
  nsCOMPtr<nsISFVService> sfv = net::GetSFVService();
  NS_ENSURE_TRUE(sfv, NS_ERROR_FAILURE);

  nsCOMPtr<nsISFVDictionary> dict;
  nsresult rv = sfv->ParseDictionary(aHeader, getter_AddRefs(dict));

  if (NS_FAILED(rv)) {
    return rv;
  }

  nsCOMPtr<nsISFVItemOrInnerList> manifest;
  MOZ_TRY(dict->Get("manifest"_ns, getter_AddRefs(manifest)));

  MOZ_DBG(manifest);

  nsCOMPtr<nsISFVItem> manifestItem = do_QueryInterface(manifest);
  if (!manifestItem) {
    return NS_ERROR_FAILURE;
  }

  MOZ_DBG(manifestItem);

  nsCOMPtr<nsISFVBareItem> value;
  MOZ_TRY(manifestItem->GetValue(getter_AddRefs(value)));

  if (nsCOMPtr<nsISFVString> stringVal = do_QueryInterface(value)) {
    nsAutoCString manifestURL;
    MOZ_TRY(stringVal->GetValue(manifestURL));

    MOZ_DBG(manifestURL);
  }

  return NS_OK;
}

nsresult SiteIntegrityService::HasMatchingHost(
    const nsACString& aHost, const OriginAttributes& aOriginAttributes,
    bool* outMatch) {}
