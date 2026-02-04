/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "SiteIntegrityService.h"

#include "mozilla/Logging.h"
#include "mozilla/net/SFVService.h"
#include "nsIDataStorage.h"
#include "prtime.h"

using namespace mozilla;

static LazyLogModule gSiteIntegrityLog("SiteIntegrity");

NS_IMPL_ISUPPORTS(SiteIntegrityService, nsISiteIntegrityService)

SiteIntegrityService::~SiteIntegrityService() = default;

nsresult SiteIntegrityService::Init() {
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
              "Initializing SiteIntegrityService");

  nsCOMPtr<nsIDataStorageManager> dataStorageManager(
      do_GetService("@mozilla.org/security/datastoragemanager;1"));
  if (!dataStorageManager) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to get DataStorageManager");
    return NS_ERROR_FAILURE;
  }

  MOZ_TRY(
      dataStorageManager->Get(nsIDataStorageManager::SiteIntegrityServiceState,
                              getter_AddRefs(mDataStorage)));

  if (!mDataStorage) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to get DataStorage");
    return NS_ERROR_FAILURE;
  }

  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
              "SiteIntegrityService initialized successfully");
  return NS_OK;
}

NS_IMETHODIMP
SiteIntegrityService::ProcessHeader(nsIURI* aSourceURI,
                                    const nsACString& aHeader,
                                    const OriginAttributes& aOriginAttributes) {
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug, "ProcessHeader: {}",
              PromiseFlatCString(aHeader));

  uint64_t maxAge;
  nsresult rv = ParseHeader(aHeader, &maxAge);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to parse header: {:x}", static_cast<uint32_t>(rv));
    return rv;
  }

  nsAutoCString storageKey;
  nsIDataStorage::DataType storageType;
  rv = GetStorageKeyFromURI(aSourceURI, aOriginAttributes, storageKey,
                            &storageType);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "Failed to get storage key: {:x}", static_cast<uint32_t>(rv));
    return rv;
  }

  PRTime now = PR_Now();
  PRTime expirationTime = now + (static_cast<PRTime>(maxAge) * PR_USEC_PER_SEC);

  nsAutoCString expirationString;
  expirationString.AppendInt(expirationTime);

  mDataStorage->Put(storageKey, expirationString, storageType);

  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
              "Header processed successfully, expires at: {}", expirationTime);
  return NS_OK;
}

static nsresult ParseMaxAge(nsISFVDictionary* aDict, uint64_t* outMaxAge) {
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

static nsresult ParseManifest(nsISFVDictionary* aDict,
                              nsACString& outManifest) {
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

nsresult SiteIntegrityService::ParseHeader(const nsACString& aHeader,
                                           uint64_t* outMaxAge) {
  nsCOMPtr<nsISFVService> sfv = net::GetSFVService();
  NS_ENSURE_TRUE(sfv, NS_ERROR_FAILURE);

  nsCOMPtr<nsISFVDictionary> dict;
  MOZ_TRY(sfv->ParseDictionary(aHeader, getter_AddRefs(dict)));

  uint64_t maxAge;
  MOZ_TRY(ParseMaxAge(dict, &maxAge));
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug, "max-age: {}", maxAge);

  nsAutoCString manifest;
  MOZ_TRY(ParseManifest(dict, manifest));
  MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug, "Manifest URL: {}", manifest);

  *outMaxAge = maxAge;
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
    nsACString& outStorageKey, nsIDataStorage::DataType* outStorageType) {
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

  *outStorageType = aOriginAttributes.IsPrivateBrowsing()
                        ? nsIDataStorage::DataType::Private
                        : nsIDataStorage::DataType::Persistent;

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
  nsIDataStorage::DataType storageType;
  nsresult rv =
      GetStorageKeyFromURI(aURI, aOriginAttributes, storageKey, &storageType);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "IsProtectedURI: Failed to get storage key: {:x}",
                static_cast<uint32_t>(rv));
    return rv;
  }

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

  if (value.IsEmpty()) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
                "IsProtectedURI: Empty value found");
    *outMatch = false;
    return NS_OK;
  }

  nsresult conversionResult;
  PRTime storedExpirationTime = value.ToInteger64(&conversionResult);
  if (NS_FAILED(conversionResult)) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Warning,
                "IsProtectedURI: Failed to parse expiration time");
    *outMatch = false;
    return NS_OK;
  }

  PRTime now = PR_Now();
  bool isExpired = now >= storedExpirationTime;

  if (isExpired) {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
                "IsProtectedURI: Entry has expired (now: {}, expiration: {})",
                now, storedExpirationTime);
    mDataStorage->Remove(storageKey, storageType);
    *outMatch = false;
  } else {
    MOZ_LOG_FMT(gSiteIntegrityLog, LogLevel::Debug,
                "IsProtectedURI: Entry is valid (now: {}, expiration: {})", now,
                storedExpirationTime);
    *outMatch = true;
  }

  return NS_OK;
}
