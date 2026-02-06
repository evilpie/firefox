/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "IntegrityPolicy.h"

#include "WAICTLog.h"
#include "WAICTUtils.h"
#include "mozilla/Logging.h"
#include "mozilla/NotNull.h"
#include "mozilla/StaticPrefs_security.h"
#include "mozilla/dom/Document.h"
#include "mozilla/dom/RequestBinding.h"
#include "mozilla/dom/WindowGlobalChild.h"
#include "mozilla/ipc/PBackgroundSharedTypes.h"
#include "mozilla/net/SFVService.h"
#include "nsCOMPtr.h"
#include "nsContentUtils.h"
#include "nsIClassInfoImpl.h"
#include "nsIObjectInputStream.h"
#include "nsIObjectOutputStream.h"
#include "nsIScriptError.h"
#include "nsString.h"

using namespace mozilla;

static LazyLogModule sIntegrityPolicyLogModule("IntegrityPolicy");
#define LOG(fmt, ...) \
  MOZ_LOG_FMT(sIntegrityPolicyLogModule, LogLevel::Debug, fmt, ##__VA_ARGS__)

namespace mozilla::dom {

IntegrityPolicy::~IntegrityPolicy() {
  // Stop asserting about promise not being rejected before it's destroyed.
  if (mWAICTPromise) {
    mWAICTPromise->Reject(false, __func__);
  }
}

void IntegrityPolicy::FlushConsoleMessages() {
  mQueueUpMessages = false;

  if (!mDocument) {
    mConsoleMsgQueue.Clear();
    return;
  }

  for (const auto& elem : mConsoleMsgQueue) {
    nsContentUtils::ReportToConsole(elem.mErrorFlags, elem.mCategory, mDocument,
                                    nsContentUtils::eSECURITY_PROPERTIES,
                                    elem.mMessageName.get(), elem.mParams);
  }
  mConsoleMsgQueue.Clear();
}

RequestDestination ContentTypeToDestination(nsContentPolicyType aType) {
  // From SecFetch.cpp
  // https://searchfox.org/mozilla-central/rev/f1e32fa7054859d37eea8804e220dfcc7fb53b03/dom/security/SecFetch.cpp#24-32
  switch (aType) {
    case nsIContentPolicy::TYPE_INTERNAL_SCRIPT:
    case nsIContentPolicy::TYPE_INTERNAL_SCRIPT_PRELOAD:
    case nsIContentPolicy::TYPE_INTERNAL_MODULE:
    case nsIContentPolicy::TYPE_INTERNAL_MODULE_PRELOAD:
    // We currently only support documents.
    // case nsIContentPolicy::TYPE_INTERNAL_WORKER_IMPORT_SCRIPTS:
    case nsIContentPolicy::TYPE_INTERNAL_CHROMEUTILS_COMPILED_SCRIPT:
    case nsIContentPolicy::TYPE_INTERNAL_FRAME_MESSAGEMANAGER_SCRIPT:
    case nsIContentPolicy::TYPE_SCRIPT:
      return RequestDestination::Script;

    case nsIContentPolicy::TYPE_STYLESHEET:
    case nsIContentPolicy::TYPE_INTERNAL_STYLESHEET:
    case nsIContentPolicy::TYPE_INTERNAL_STYLESHEET_PRELOAD:
      return RequestDestination::Style;

    default:
      return RequestDestination::_empty;
  }
}

Maybe<IntegrityPolicy::DestinationType> DOMRequestDestinationToDestinationType(
    RequestDestination aDestination) {
  switch (aDestination) {
    case RequestDestination::Script:
      return Some(IntegrityPolicy::DestinationType::Script);
    case RequestDestination::Style:
      return StaticPrefs::security_integrity_policy_stylesheet_enabled()
                 ? Some(IntegrityPolicy::DestinationType::Style)
                 : Nothing{};

    default:
      return Nothing{};
  }
}

Maybe<IntegrityPolicy::DestinationType>
IntegrityPolicy::ContentTypeToDestinationType(nsContentPolicyType aType) {
  return DOMRequestDestinationToDestinationType(
      ContentTypeToDestination(aType));
}

nsresult GetStringsFromInnerList(nsISFVInnerList* aList, bool aIsToken,
                                 nsTArray<nsCString>& aStrings) {
  nsTArray<RefPtr<nsISFVItem>> items;
  nsresult rv = aList->GetItems(items);
  NS_ENSURE_SUCCESS(rv, rv);

  for (auto& item : items) {
    nsCOMPtr<nsISFVBareItem> value;
    rv = item->GetValue(getter_AddRefs(value));
    NS_ENSURE_SUCCESS(rv, rv);

    nsAutoCString itemStr;
    if (aIsToken) {
      nsCOMPtr<nsISFVToken> itemToken(do_QueryInterface(value));
      NS_ENSURE_TRUE(itemToken, NS_ERROR_FAILURE);

      rv = itemToken->GetValue(itemStr);
      NS_ENSURE_SUCCESS(rv, rv);
    } else {
      nsCOMPtr<nsISFVString> itemString(do_QueryInterface(value));
      NS_ENSURE_TRUE(itemString, NS_ERROR_FAILURE);

      rv = itemString->GetValue(itemStr);
      NS_ENSURE_SUCCESS(rv, rv);
    }

    aStrings.AppendElement(itemStr);
  }

  return NS_OK;
}

/* static */
Result<IntegrityPolicy::Sources, nsresult> ParseSources(
    nsISFVDictionary* aDict) {
  // sources, a list of sources, Initially empty.

  // 3. If dictionary["sources"] does not exist or if its value contains
  // "inline", append "inline" to integrityPolicy’s sources.
  nsCOMPtr<nsISFVItemOrInnerList> iil;
  nsresult rv = aDict->Get("sources"_ns, getter_AddRefs(iil));
  if (NS_FAILED(rv)) {
    // The key doesn't exists, set it to inline as per spec.
    return IntegrityPolicy::Sources(IntegrityPolicy::SourceType::Inline);
  }

  nsCOMPtr<nsISFVInnerList> il(do_QueryInterface(iil));
  NS_ENSURE_TRUE(il, Err(NS_ERROR_FAILURE));

  nsTArray<nsCString> sources;
  rv = GetStringsFromInnerList(il, true, sources);
  NS_ENSURE_SUCCESS(rv, Err(rv));

  IntegrityPolicy::Sources result;
  for (const auto& source : sources) {
    if (source.EqualsLiteral("inline")) {
      result += IntegrityPolicy::SourceType::Inline;
    } else {
      LOG("ParseSources: Unknown source: {}", source.get());
      // Unknown source, we don't know how to handle it
      continue;
    }
  }

  return result;
}

/* static */
Result<IntegrityPolicy::Destinations, nsresult> ParseDestinations(
    nsISFVDictionary* aDict, bool aIsWAICT) {
  // blocked destinations, a list of destinations, initially empty.

  nsCOMPtr<nsISFVItemOrInnerList> iil;
  nsresult rv = aDict->Get("blocked-destinations"_ns, getter_AddRefs(iil));
  if (NS_FAILED(rv)) {
    return IntegrityPolicy::Destinations();
  }

  // 4. If dictionary["blocked-destinations"] exists:
  nsCOMPtr<nsISFVInnerList> il(do_QueryInterface(iil));
  NS_ENSURE_TRUE(il, Err(NS_ERROR_FAILURE));

  nsTArray<nsCString> destinations;
  rv = GetStringsFromInnerList(il, true, destinations);
  NS_ENSURE_SUCCESS(rv, Err(rv));

  IntegrityPolicy::Destinations result;
  for (const auto& destination : destinations) {
    if (destination.EqualsLiteral("script")) {
      result += IntegrityPolicy::DestinationType::Script;
    } else if (destination.EqualsLiteral("style")) {
      if (StaticPrefs::security_integrity_policy_stylesheet_enabled()) {
        result += IntegrityPolicy::DestinationType::Style;
      }
    } else if (aIsWAICT && destination.EqualsLiteral("image")) {
      result += IntegrityPolicy::DestinationType::Image;
    } else {
      LOG("ParseDestinations: Unknown destination: {}", destination.get());
      // Unknown destination, we don't know how to handle it
      continue;
    }
  }

  return result;
}

/* static */
Result<nsTArray<nsCString>, nsresult> ParseEndpoints(nsISFVDictionary* aDict) {
  // endpoints, a list of strings, initially empty.
  nsCOMPtr<nsISFVItemOrInnerList> iil;
  nsresult rv = aDict->Get("endpoints"_ns, getter_AddRefs(iil));
  if (NS_FAILED(rv)) {
    // The key doesn't exists, return empty list.
    return nsTArray<nsCString>();
  }

  nsCOMPtr<nsISFVInnerList> il(do_QueryInterface(iil));
  NS_ENSURE_TRUE(il, Err(NS_ERROR_FAILURE));
  nsTArray<nsCString> endpoints;
  rv = GetStringsFromInnerList(il, true, endpoints);
  NS_ENSURE_SUCCESS(rv, Err(rv));

  return endpoints;
}

/* static */
// https://w3c.github.io/webappsec-subresource-integrity/#processing-an-integrity-policy
nsresult IntegrityPolicy::ParseHeaders(const nsACString& aHeader,
                                       const nsACString& aHeaderRO,
                                       const nsACString& aWaict,
                                       nsIURI* aDocumentURI,
                                       IntegrityPolicy** aPolicy,
                                       Document* aDocument) {
  if (!StaticPrefs::security_integrity_policy_enabled()) {
    return NS_OK;
  }

  // 1. Let integrityPolicy be a new integrity policy struct.
  // (Our struct contains two entries, one for the enforcement header and one
  // for report-only)
  RefPtr<IntegrityPolicy> policy = new IntegrityPolicy();

  LOG("[{}] Parsing headers: enforcement='{}' report-only='{}'",
      static_cast<void*>(policy), aHeader.Data(), aHeaderRO.Data());

  nsCOMPtr<nsISFVService> sfv = net::GetSFVService();
  NS_ENSURE_TRUE(sfv, NS_ERROR_FAILURE);

  for (const auto& isROHeader : {false, true}) {
    const auto& headerString = isROHeader ? aHeaderRO : aHeader;

    if (headerString.IsEmpty()) {
      LOG("[{}] No {} header.", static_cast<void*>(policy),
          isROHeader ? "report-only" : "enforcement");
      continue;
    }

    // 2. Let dictionary be the result of getting a structured field value from
    // headers given headerName and "dictionary".
    nsCOMPtr<nsISFVDictionary> dict;
    nsresult rv = sfv->ParseDictionary(headerString, getter_AddRefs(dict));
    if (NS_FAILED(rv)) {
      LOG("[{}] Failed to parse {} header.", static_cast<void*>(policy),
          isROHeader ? "report-only" : "enforcement");
      continue;
    }

    // 3. If dictionary["sources"] does not exist or if its value contains
    // "inline", append "inline" to integrityPolicy’s sources.
    auto sourcesResult = ParseSources(dict);
    if (sourcesResult.isErr()) {
      LOG("[{}] Failed to parse sources for {} header.",
          static_cast<void*>(policy),
          isROHeader ? "report-only" : "enforcement");
      continue;
    }

    // 4. If dictionary["blocked-destinations"] exists:
    auto destinationsResult = ParseDestinations(dict, /* aIsWAICT */ false);
    if (destinationsResult.isErr()) {
      LOG("[{}] Failed to parse destinations for {} header.",
          static_cast<void*>(policy),
          isROHeader ? "report-only" : "enforcement");
      continue;
    }

    // 5. If dictionary["endpoints"] exists:
    auto endpointsResult = ParseEndpoints(dict);
    if (endpointsResult.isErr()) {
      LOG("[{}] Failed to parse endpoints for {} header.",
          static_cast<void*>(policy),
          isROHeader ? "report-only" : "enforcement");
      continue;
    }

    LOG("[{}] Creating policy for {} header. sources={} destinations={} "
        "endpoints=[{}]",
        static_cast<void*>(policy), isROHeader ? "report-only" : "enforcement",
        sourcesResult.unwrap().serialize(),
        destinationsResult.unwrap().serialize(),
        fmt::join(endpointsResult.unwrap(), ", "));

    Entry entry = Entry(sourcesResult.unwrap(), destinationsResult.unwrap(),
                        endpointsResult.unwrap());
    if (isROHeader) {
      policy->mReportOnly.emplace(entry);
    } else {
      policy->mEnforcement.emplace(entry);
    }
  }

  policy->ParseWaict(aDocumentURI, aWaict, aDocument);

  // 6. Return integrityPolicy.
  policy.forget(aPolicy);

  LOG("[{}] Finished parsing headers.", static_cast<void*>(policy));

  return NS_OK;
}

bool IntegrityPolicy::HasWaictFor(DestinationType aDestination) {
  return !mWaictManifestURL.IsEmpty() &&
         mWaictDestinations.contains(aDestination);
}

RefPtr<IntegrityPolicy::WAICTManifestLoadedPromise>
IntegrityPolicy::WaitForManifestLoad() {
  MOZ_ASSERT(!mWaictManifestURL.IsEmpty());
  return mWAICTPromise;
}

bool IntegrityPolicy::CheckHash(nsIURI* aURI, const nsACString& aHash,
                                Document* aDocument) {
  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "IntegrityPolicy::CheckHash aURI = {} aHash = {}",
              aURI->GetSpecOrDefault().get(), nsCString(aHash).get());

  // First, try path-based lookup in hashes
  if (!mHashesLookup.IsEmpty()) {
    nsAutoCString path;
    // https://searchfox.org/firefox-main/source/netwerk/base/DefaultURI.cpp#135
    // TODO: is it the best/correct way? 
    nsresult rv = aURI->GetPathQueryRef(path);
    if (NS_SUCCEEDED(rv)) {
      nsString* hashValue = mHashesLookup.Lookup(NS_ConvertUTF8toUTF16(path));

      if (hashValue) {
        // Found in path-based hashes, validate the hash value
        nsCString hashEntry = NS_ConvertUTF16toUTF8(*hashValue);

        if (hashEntry != aHash) {
          MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                      "IntegrityPolicy::CheckHash: Wrong hash for path ({} != {})",
                      hashEntry.get(), nsCString(aHash).get());
          return false;
        }

        MOZ_LOG_FMT(gWaictLog, LogLevel::Info,
                    "IntegrityPolicy::CheckHash: Correct hash (path-based)");
        return true;
      }
    }
  }

  // If not found in path-based hashes, check any_hashes
  if (!mAnyHashesLookup.IsEmpty()) {
    nsString hashStr = NS_ConvertUTF8toUTF16(aHash);

    if (mAnyHashesLookup.Contains(hashStr)) {
      MOZ_LOG_FMT(gWaictLog, LogLevel::Info,
                  "IntegrityPolicy::CheckHash: Hash found in any_hashes");
      return true;
    }
  }

  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "IntegrityPolicy::CheckHash: Hash not found in either lookup");
  return false;
}

nsresult IntegrityPolicy::ParseWaict(nsIURI* aDocumentURI,
                                     const nsACString& aHeader,
                                     Document* aDocument) {
  if (aHeader.IsEmpty()) {
    return NS_OK;
  }

  mDocument = aDocument;
  mDocumentURI = aDocumentURI;

  nsCOMPtr<nsISFVService> sfv = net::GetSFVService();
  if (!sfv) {
    return NS_ERROR_FAILURE;
  }

  nsCOMPtr<nsISFVDictionary> dict;
  nsresult rv = sfv->ParseDictionary(aHeader, getter_AddRefs(dict));
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseWaict: ParseDictionary failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                         "WAICTHeaderParseError", params);
    return rv;
  }

  auto destinationsResult = ParseDestinations(dict, /* aIsWAICT */ true);
  if (destinationsResult.isErr()) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseWaict: ParseDestinations failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                         "WAICTHeaderBlockedDestinationsParseError", params);

    return destinationsResult.unwrapErr();
  }

  mWaictDestinations = destinationsResult.unwrap();

  rv = waict::ParseMaxAge(dict, &mWaictMaxAge);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseWaict: waict::ParseMaxAge failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                         "WAICTHeaderMaxAgeParseError", params);

    return rv;
  }

  rv = waict::ParseManifest(dict, mWaictManifestURL);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseWaict: waict::ParseManifest failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                         "WAICTHeaderManifestParseError", params);

    return rv;
  }

  FetchWaictManifest();
  return NS_OK;
}

// It's probably already exists somewhere in Firefox
bool IsValidBase64(const nsACString& aBase64) {
  if (aBase64.IsEmpty()) {
    return false;
  }

  for (uint32_t i = 0; i < aBase64.Length(); i++) {
    char c = aBase64.CharAt(i);
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) {
      return false;
    }
  }

  int paddingStart = aBase64.FindChar('=');
  if (paddingStart != kNotFound) {
    for (uint32_t i = paddingStart; i < aBase64.Length(); i++) {
      if (aBase64.CharAt(i) != '=') {
        return false;
      }
    }
  }

  return true;
}

// We accept both "sha256-<base64>" and "<base64>" formats
static bool ValidateHashValue(const nsAString& aHash) {
  NS_ConvertUTF16toUTF8 hash(aHash);

  if (!IsValidBase64(hash)) {
    return false;
  }

  // SHA-256 produces 32 bytes -> 43 or 44 chars in base64
  if (hash.Length() != 43 && hash.Length() != 44) {
    return false;
  }

  // If 44 chars, must end with exactly one '='
  if (hash.Length() == 44 && hash[43] != '=') {
    return false;
  }

  // If 43 chars, must not contain '='
  if (hash.Length() == 43 && hash.Contains('=')) {
    return false;
  }

  return true;
}

bool ValidateHashes(const Record<nsString, nsString>& aHashes) {
  for (const auto& entry : aHashes.Entries()) {
    if (entry.mKey.IsEmpty() || entry.mValue.IsEmpty() ||
        !ValidateHashValue(entry.mValue)) {
      return false;
    }
  }

  return true;
}

bool ValidateAnyHashes(const Sequence<nsString>& aAnyHashes) {
  for (const auto& hash : aAnyHashes) {
    if (hash.IsEmpty() || !ValidateHashValue(hash)) {
      return false;
    }
  }

  return true;
}

IntegrityPolicy::ManifestValidationStatus
IntegrityPolicy::ValidateManifest(const nsACString& aManifestJSON,
                                          WAICTManifest& aOutManifest) {
  if (!aOutManifest.Init(NS_ConvertUTF8toUTF16(aManifestJSON))) {
    // ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
    //                      "WAICTManifestJSONParseError", {});
    return ManifestValidationStatus::InvalidJSON;
  }

  // Only the version 1 is supported for now.
  if (aOutManifest.mVersion != 1) {
    // ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
    //                      "WAICTManifestJSONParseError", {});
    return ManifestValidationStatus::InvalidVersion;
  }

  // Note: Duplicate keys in the hashes record are impossible - the JSON parser
  // and record<> type automatically keep only the last value for duplicate keys.
  // At least one of hashes or any_hashes must be present and non-empty
  bool hasHashes = aOutManifest.mHashes.WasPassed() &&
                   !aOutManifest.mHashes.Value().Entries().IsEmpty();
  bool hasAnyHashes = aOutManifest.mAny_hashes.WasPassed() &&
                      !aOutManifest.mAny_hashes.Value().IsEmpty();

  if (!hasHashes && !hasAnyHashes) {
    return ManifestValidationStatus::MissingHashes;
  }

  // Validate hashes if present
  if (hasHashes && !ValidateHashes(aOutManifest.mHashes.Value())) {
    return ManifestValidationStatus::InvalidHashFormat;
  }

  // Validate any_hashes if present
  if (hasAnyHashes && !ValidateAnyHashes(aOutManifest.mAny_hashes.Value())) {
    return ManifestValidationStatus::InvalidHashFormat;
  }

  return ManifestValidationStatus::OK;
}

NS_IMETHODIMP IntegrityPolicy::OnStreamComplete(nsIStreamLoader* aLoader,
                                                nsISupports* context,
                                                nsresult aStatus,
                                                uint32_t aDataLen,
                                                const uint8_t* aData) {
  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "IntegrityPolicy::OnStreamComplete: dataLen = {}", aDataLen);

  if (NS_FAILED(aStatus)) {
    mWAICTPromise->Reject(false, __func__);
    return NS_OK;
  }

  // We can move this to ValidateManifest if we want.
  nsDependentCSubstring data(reinterpret_cast<const char*>(aData), aDataLen);
  ManifestValidationStatus status = ValidateManifest(data, mWaictManifest);
  if (status != ManifestValidationStatus::OK) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "Failed to validate WAICT manifest, error= {}",
                static_cast<uint8_t>(status));
    mWAICTPromise->Reject(false, __func__);
    return NS_OK;
  }

  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug, ("Manifest Validation success"));

  if (mDocument && mDocumentURI) {
    if (WindowGlobalChild* wgc = mDocument->GetWindowGlobalChild()) {
      wgc->SendSetSiteIntegrityProtected(WrapNotNull(mDocumentURI.get()),
                                         mWaictMaxAge);
    }
  }

  // JSON mHashes/AnyHashes are represented as arrays after parsing
  // If we don't want to have O(n) (where n can be 10-100k) lookup
  // We need to translate it to hashset/hashmap

  // If mHashes are not empty
  if (mWaictManifest.mHashes.WasPassed()) {
    const auto& entries = mWaictManifest.mHashes.Value().Entries();
    mHashesLookup.Clear();
    mHashesLookup.Reserve(entries.Length());
    for (const auto& entry : entries) {
      mHashesLookup.InsertOrUpdate(entry.mKey, entry.mValue);
    }
    // AW: remove if too much of logging :) same below
    MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
                "Built hash lookup table with {} entries", entries.Length());
  }

  // If mAnyHashes are not empty
  if (mWaictManifest.mAny_hashes.WasPassed()) {
    const auto& hashes = mWaictManifest.mAny_hashes.Value();
    mAnyHashesLookup.Clear();
    mAnyHashesLookup.Reserve(hashes.Length());
    for (const auto& hash : hashes) {
      mAnyHashesLookup.Insert(hash);
    }
    MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
                "Built any_hashes lookup set with {} entries", hashes.Length());
  }

  MOZ_LOG_FMT(gWaictLog, LogLevel::Info, "Got manifest, version={}",
              mWaictManifest.mVersion);
  mWAICTPromise->Resolve(true, __func__);
  return NS_OK;
}

void IntegrityPolicy::FetchWaictManifest() {
  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "FetchWaictManifest: mWaictManifestURL={}",
              mWaictManifestURL.get());

  mWAICTPromise = MakeRefPtr<WAICTManifestLoadedPromise::Private>(__func__);

  nsCOMPtr<nsIURI> uri;
  nsresult rv =
      NS_NewURI(getter_AddRefs(uri), mWaictManifestURL, nullptr, mDocumentURI);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "Could not parse manifest URL: rv={}",
                static_cast<uint32_t>(rv));
    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(mWaictManifestURL)};
    ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                         "WAICTManifestFetchURLParseError", params);
    mWAICTPromise->Reject(true, __func__);
    return;
  }

  nsCOMPtr<nsIStreamLoader> loader;
  // XXX use right flags.
  rv = NS_NewStreamLoader(
      getter_AddRefs(loader), uri, this, nsContentUtils::GetSystemPrincipal(),
      nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
      nsIContentPolicy::TYPE_OTHER);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "Could not fetch manifest URL: rv = {}",
                static_cast<uint32_t>(rv));
    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(mWaictManifestURL)};
    ReportOrQueueMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                         "WAICTManifestFetchError", params);
    mWAICTPromise->Reject(true, __func__);
  }
}

void IntegrityPolicy::ReportOrQueueMessage(uint32_t aErrorFlags,
                                           const nsACString& aCategory,
                                           const char* aMessageName,
                                           const nsTArray<nsString>& aParams) {
  if (mQueueUpMessages) {
    IPConsoleMsgQueueElem& elem = *mConsoleMsgQueue.AppendElement();
    elem.mErrorFlags = aErrorFlags;
    elem.mCategory = aCategory;
    elem.mMessageName = nsCString(aMessageName);
    elem.mParams = aParams.Clone();
    return;
  }

  if (mDocument) {
    nsContentUtils::ReportToConsole(aErrorFlags, aCategory, mDocument,
                                    nsContentUtils::eSECURITY_PROPERTIES,
                                    aMessageName, aParams);
  }
}

void IntegrityPolicy::PolicyContains(DestinationType aDestination,
                                     bool* aContains, bool* aROContains) const {
  // 10. Let block be a boolean, initially false.
  *aContains = false;
  // 11. Let reportBlock be a boolean, initially false.
  *aROContains = false;

  // 12. If policy’s sources contains "inline" and policy’s blocked destinations
  // contains request’s destination, set block to true.
  if (mEnforcement && mEnforcement->mDestinations.contains(aDestination) &&
      mEnforcement->mSources.contains(SourceType::Inline)) {
    *aContains = true;
  }

  // 13. If reportPolicy’s sources contains "inline" and reportPolicy’s blocked
  // destinations contains request’s destination, set reportBlock to true.
  if (mReportOnly && mReportOnly->mDestinations.contains(aDestination) &&
      mReportOnly->mSources.contains(SourceType::Inline)) {
    *aROContains = true;
  }
}

void IntegrityPolicy::Endpoints(nsTArray<nsCString>& aEnforcement,
                                nsTArray<nsCString>& aReportOnly) const {
  if (mEnforcement) {
    aEnforcement = mEnforcement->mEndpoints.Clone();
  }
  if (mReportOnly) {
    aReportOnly = mReportOnly->mEndpoints.Clone();
  }
}

void IntegrityPolicy::ToArgs(const IntegrityPolicy* aPolicy,
                             mozilla::ipc::IntegrityPolicyArgs& aArgs) {
  aArgs.enforcement() = Nothing();
  aArgs.reportOnly() = Nothing();

  if (!aPolicy) {
    return;
  }

  if (aPolicy->mEnforcement) {
    mozilla::ipc::IntegrityPolicyEntry entry;
    entry.sources() = aPolicy->mEnforcement->mSources;
    entry.destinations() = aPolicy->mEnforcement->mDestinations;
    entry.endpoints() = aPolicy->mEnforcement->mEndpoints.Clone();
    aArgs.enforcement() = Some(entry);
  }

  if (aPolicy->mReportOnly) {
    mozilla::ipc::IntegrityPolicyEntry entry;
    entry.sources() = aPolicy->mReportOnly->mSources;
    entry.destinations() = aPolicy->mReportOnly->mDestinations;
    entry.endpoints() = aPolicy->mReportOnly->mEndpoints.Clone();
    aArgs.reportOnly() = Some(entry);
  }
}

void IntegrityPolicy::FromArgs(const mozilla::ipc::IntegrityPolicyArgs& aArgs,
                               IntegrityPolicy** aPolicy) {
  RefPtr<IntegrityPolicy> policy = new IntegrityPolicy();

  if (aArgs.enforcement().isSome()) {
    const auto& entry = *aArgs.enforcement();
    policy->mEnforcement.emplace(Entry(entry.sources(), entry.destinations(),
                                       entry.endpoints().Clone()));
  }

  if (aArgs.reportOnly().isSome()) {
    const auto& entry = *aArgs.reportOnly();
    policy->mReportOnly.emplace(Entry(entry.sources(), entry.destinations(),
                                      entry.endpoints().Clone()));
  }

  policy.forget(aPolicy);
}

void IntegrityPolicy::InitFromOther(IntegrityPolicy* aOther) {
  if (!aOther) {
    return;
  }

  if (aOther->mEnforcement) {
    mEnforcement.emplace(Entry(*aOther->mEnforcement));
  }

  if (aOther->mReportOnly) {
    mReportOnly.emplace(Entry(*aOther->mReportOnly));
  }
}

bool IntegrityPolicy::Equals(const IntegrityPolicy* aPolicy,
                             const IntegrityPolicy* aOtherPolicy) {
  // Do a quick pointer check first, also checks if both are null.
  if (aPolicy == aOtherPolicy) {
    return true;
  }

  // We checked if they were null above, so make sure one of them is not null.
  if (!aPolicy || !aOtherPolicy) {
    return false;
  }

  if (!Entry::Equals(aPolicy->mEnforcement, aOtherPolicy->mEnforcement)) {
    return false;
  }

  if (!Entry::Equals(aPolicy->mReportOnly, aOtherPolicy->mReportOnly)) {
    return false;
  }

  return true;
}

bool IntegrityPolicy::Entry::Equals(const Maybe<Entry>& aPolicy,
                                    const Maybe<Entry>& aOtherPolicy) {
  // If one is set and the other is not, they are not equal.
  if (aPolicy.isSome() != aOtherPolicy.isSome()) {
    return false;
  }

  // If both are not set, they are equal.
  if (aPolicy.isNothing() && aOtherPolicy.isNothing()) {
    return true;
  }

  if (aPolicy->mSources != aOtherPolicy->mSources) {
    return false;
  }

  if (aPolicy->mDestinations != aOtherPolicy->mDestinations) {
    return false;
  }

  if (aPolicy->mEndpoints != aOtherPolicy->mEndpoints) {
    return false;
  }

  return true;
}

constexpr static const uint32_t kIntegrityPolicySerializationVersion = 1;

NS_IMETHODIMP
IntegrityPolicy::Read(nsIObjectInputStream* aStream) {
  nsresult rv;

  uint32_t version;
  rv = aStream->Read32(&version);
  NS_ENSURE_SUCCESS(rv, rv);

  if (version != kIntegrityPolicySerializationVersion) {
    LOG("IntegrityPolicy::Read: Unsupported version: {}", version);
    return NS_ERROR_FAILURE;
  }

  for (const bool& isRO : {false, true}) {
    bool hasPolicy;
    rv = aStream->ReadBoolean(&hasPolicy);
    NS_ENSURE_SUCCESS(rv, rv);

    if (!hasPolicy) {
      continue;
    }

    uint32_t sources;
    rv = aStream->Read32(&sources);
    NS_ENSURE_SUCCESS(rv, rv);

    Sources sourcesSet;
    sourcesSet.deserialize(sources);

    uint32_t destinations;
    rv = aStream->Read32(&destinations);
    NS_ENSURE_SUCCESS(rv, rv);

    Destinations destinationsSet;
    destinationsSet.deserialize(destinations);

    uint32_t endpointsLen;
    rv = aStream->Read32(&endpointsLen);
    NS_ENSURE_SUCCESS(rv, rv);

    nsTArray<nsCString> endpoints(endpointsLen);
    for (size_t endpointI = 0; endpointI < endpointsLen; endpointI++) {
      nsCString endpoint;
      rv = aStream->ReadCString(endpoint);
      NS_ENSURE_SUCCESS(rv, rv);
      endpoints.AppendElement(std::move(endpoint));
    }

    Entry entry = Entry(sourcesSet, destinationsSet, std::move(endpoints));
    if (isRO) {
      mReportOnly.emplace(entry);
    } else {
      mEnforcement.emplace(entry);
    }
  }

  return NS_OK;
}

NS_IMETHODIMP
IntegrityPolicy::Write(nsIObjectOutputStream* aStream) {
  nsresult rv;

  rv = aStream->Write32(kIntegrityPolicySerializationVersion);
  NS_ENSURE_SUCCESS(rv, rv);

  for (const auto& entry : {mEnforcement, mReportOnly}) {
    if (!entry) {
      aStream->WriteBoolean(false);
      continue;
    }

    aStream->WriteBoolean(true);

    rv = aStream->Write32(entry->mSources.serialize());
    NS_ENSURE_SUCCESS(rv, rv);

    rv = aStream->Write32(entry->mDestinations.serialize());
    NS_ENSURE_SUCCESS(rv, rv);

    rv = aStream->Write32(entry->mEndpoints.Length());
    for (const auto& endpoint : entry->mEndpoints) {
      rv = aStream->WriteCString(endpoint);
      NS_ENSURE_SUCCESS(rv, rv);
    }
  }

  return NS_OK;
}

NS_IMPL_CLASSINFO(IntegrityPolicy, nullptr, 0, NS_IINTEGRITYPOLICY_IID)
NS_IMPL_ISUPPORTS_CI(IntegrityPolicy, nsIIntegrityPolicy, nsISerializable,
                     nsIStreamLoaderObserver)

}  // namespace mozilla::dom

#undef LOG
