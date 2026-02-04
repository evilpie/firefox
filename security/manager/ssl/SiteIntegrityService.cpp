/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "SiteIntegrityService.h"

#include "mozilla/Logging.h"
#include "mozilla/net/SFVService.h"
#include "nsIDataStorage.h"

using namespace mozilla;

static LazyLogModule gSiteIntegrityLog("SiteIntegrity");

NS_IMPL_ISUPPORTS(SiteIntegrityService, nsISiteIntegrityService)

SiteIntegrityService::~SiteIntegrityService() = default;

nsresult SiteIntegrityService::Init() {
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug, "Initializing SiteIntegrityService");

  nsCOMPtr<nsIDataStorageManager> dataStorageManager(
      do_GetService("@mozilla.org/security/datastoragemanager;1"));
  if (!dataStorageManager) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning, "Failed to get DataStorageManager");
    return NS_ERROR_FAILURE;
  }

  MOZ_TRY(
      dataStorageManager->Get(nsIDataStorageManager::SiteIntegrityServiceState,
                              getter_AddRefs(mDataStorage)));

  if (!mDataStorage) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning, "Failed to get DataStorage");
    return NS_ERROR_FAILURE;
  }

  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug, "SiteIntegrityService initialized successfully");
  return NS_OK;
}

NS_IMETHODIMP
SiteIntegrityService::ProcessHeader(nsIURI* aSourceURI,
                                    const nsACString& aHeader,
                                    const OriginAttributes& aOriginAttributes) {
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
              "ProcessHeader: {}", PromiseFlatCString(aHeader));

  nsresult rv = ParseHeader(aHeader);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to parse header: {:x}", static_cast<uint32_t>(rv));
    return rv;
  }

  nsAutoCString storageKey;
  rv = GetStorageKeyFromURI(aSourceURI, aOriginAttributes, storageKey);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to get storage key: {:x}", static_cast<uint32_t>(rv));
    return rv;
  }

  nsIDataStorage::DataType storageType =
      aOriginAttributes.IsPrivateBrowsing()
          ? nsIDataStorage::DataType::Private
          : nsIDataStorage::DataType::Persistent;

// Remember that we had a WAICT header for this load.
  mDataStorage->Put(storageKey, "hello world"_ns, storageType);

  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug, "Header processed successfully");
  return NS_OK;
}

nsresult SiteIntegrityService::ParseHeader(const nsACString& aHeader) {
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Verbose, "Parsing header");

  nsCOMPtr<nsISFVService> sfv = net::GetSFVService();
  NS_ENSURE_TRUE(sfv, NS_ERROR_FAILURE);

  nsCOMPtr<nsISFVDictionary> dict;
  nsresult rv = sfv->ParseDictionary(aHeader, getter_AddRefs(dict));

  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to parse dictionary: {:x}", static_cast<uint32_t>(rv));
    return rv;
  }

  nsCOMPtr<nsISFVItemOrInnerList> manifest;
  rv = dict->Get("manifest"_ns, getter_AddRefs(manifest));
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning, "No manifest field in header");
    return rv;
  }

  nsCOMPtr<nsISFVItem> manifestItem = do_QueryInterface(manifest);
  if (!manifestItem) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning, "Manifest is not an item");
    return NS_ERROR_FAILURE;
  }

  nsCOMPtr<nsISFVBareItem> value;
  MOZ_TRY(manifestItem->GetValue(getter_AddRefs(value)));

  nsCOMPtr<nsISFVString> stringVal = do_QueryInterface(value);
  if (!stringVal) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning, "Manifest value is not a string");
    return NS_ERROR_FAILURE;
  }

  nsAutoCString manifestURL;
  MOZ_TRY(stringVal->GetValue(manifestURL));

  if (manifestURL.IsEmpty()) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning, "Manifest URL is empty");
    return NS_ERROR_FAILURE;
  }

  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug, "Manifest URL: {}", manifestURL);

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

nsresult SiteIntegrityService::GetStorageKeyFromURI(
    nsIURI* aURI, const OriginAttributes& aOriginAttributes,
    nsACString& outStorageKey) {
  nsAutoCString host;
  nsresult rv = GetHost(aURI, host);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to get host from URI: {:x}", static_cast<uint32_t>(rv));
    return rv;
  }

  nsAutoCString storageKey;
  GetStorageKey(host, aOriginAttributes, storageKey);
  outStorageKey.Assign(storageKey);

  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Verbose,
              "Generated storage key: {} for host: {}", storageKey, host);

  return NS_OK;
}

NS_IMETHODIMP
SiteIntegrityService::IsProtectedURI(nsIURI* aURI,
                                     const OriginAttributes& aOriginAttributes,
                                     bool* outMatch) {
  NS_ENSURE_ARG_POINTER(aURI);
  NS_ENSURE_ARG_POINTER(outMatch);

  *outMatch = false;

  nsAutoCString storageKey;
  nsresult rv = GetStorageKeyFromURI(aURI, aOriginAttributes, storageKey);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "IsProtectedURI: Failed to get storage key: {:x}",
                static_cast<uint32_t>(rv));
    return rv;
  }

  nsIDataStorage::DataType storageType =
      aOriginAttributes.IsPrivateBrowsing()
          ? nsIDataStorage::DataType::Private
          : nsIDataStorage::DataType::Persistent;

  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Verbose,
              "IsProtectedURI: Checking storage key: {}", storageKey);

  nsAutoCString value;
  rv = mDataStorage->Get(storageKey, storageType, value);
  if (rv == NS_ERROR_NOT_AVAILABLE) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
                "IsProtectedURI: No data found for key");
    *outMatch = false;
    return NS_OK;
  }
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "IsProtectedURI: Failed to get data: {:x}",
                static_cast<uint32_t>(rv));
    return rv;
  }

  *outMatch = !value.IsEmpty();
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
              "IsProtectedURI: Match result: {}", *outMatch);

  return NS_OK;
}
