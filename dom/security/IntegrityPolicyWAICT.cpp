/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "IntegrityPolicyWAICT.h"

#include "WAICTLog.h"
#include "WAICTUtils.h"
#include "mozilla/Logging.h"
#include "mozilla/StaticPrefs_security.h"
#include "mozilla/dom/Document.h"
#include "mozilla/dom/IntegrityViolationReportBody.h"
#include "mozilla/dom/ReportingUtils.h"
#include "mozilla/dom/WindowGlobalChild.h"
#include "mozilla/net/SFVService.h"
#include "nsContentUtils.h"
#include "nsIScriptError.h"

using namespace mozilla;

namespace mozilla::dom {

NS_IMPL_ISUPPORTS(IntegrityPolicyWAICT, nsIStreamLoaderObserver)

IntegrityPolicyWAICT::IntegrityPolicyWAICT(Document* aDocument)
    : mDocument(aDocument) {}

IntegrityPolicyWAICT::~IntegrityPolicyWAICT() {
  if (mPromise) {
    mManifestValid = false;
    mPromise->Resolve(true, __func__);
  }
}

RefPtr<IntegrityPolicyWAICT::WAICTManifestLoadedPromise>
IntegrityPolicyWAICT::WaitForManifestLoad() {
  MOZ_ASSERT(!mManifestURL.IsEmpty());
  return mPromise;
}

bool IntegrityPolicyWAICT::MaybeCheckResourceIntegrity(
    nsIURI* aURI, IntegrityPolicy::DestinationType aDestination,
    const nsACString& aHash, Document* aDocument) {
  MOZ_LOG_FMT(
      gWaictLog, LogLevel::Debug,
      "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity aURI = {} aHash = {}",
      aURI->GetSpecOrDefault().get(), nsCString(aHash).get());

  // If manifest failed to load/validate, decision depends on mode
  if (!mManifestValid) {
    if (mEnforce) {
      MOZ_LOG_FMT(
          gWaictLog, LogLevel::Warning,
          "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Manifest not "
          "valid, enforce mode - blocking");
      return false;
    }
    MOZ_LOG_FMT(
        gWaictLog, LogLevel::Info,
        "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Manifest not "
        "valid, audit mode - proceeding");
    return true;
  }

  if (!mHashes.IsEmpty()) {
    nsAutoCString spec;
    nsresult rv = aURI->GetSpec(spec);
    if (NS_SUCCEEDED(rv)) {
      if (auto hashValue = mHashes.Lookup(spec)) {
        if (*hashValue != aHash) {
          MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                      "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: "
                      "Wrong hash for URL "
                      "({} != {})",
                      *hashValue, nsCString(aHash));

          nsCString spec = aURI->GetSpecOrDefault();
          nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(spec),
                                       NS_ConvertUTF8toUTF16(*hashValue),
                                       NS_ConvertUTF8toUTF16(aHash)};
          ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                        "WAICTHashMismatch", params);
          return !mEnforce;
        }

        MOZ_LOG_FMT(
            gWaictLog, LogLevel::Info,
            "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Correct hash "
            "(URL-based)");
        return true;
      }
    }
  }

  if (!mAnyHashes.IsEmpty()) {
    if (mAnyHashes.Contains(aHash)) {
      MOZ_LOG_FMT(gWaictLog, LogLevel::Info,
                  "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Hash "
                  "found in any_hashes");
      return true;
    }
  }

  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Hash not "
              "found in either "
              "lookup");

  nsCString spec = aURI->GetSpecOrDefault();
  nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(spec),
                               NS_ConvertUTF8toUTF16(aHash)};
  ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                "WAICTResourceNotInManifest", params);
  return !mEnforce;
}

/* static */
nsresult IntegrityPolicyWAICT::Create(Document* aDocument,
                                      const nsACString& aHeader,
                                      IntegrityPolicyWAICT** aPolicy) {
  NS_ENSURE_ARG_POINTER(aDocument);

  if (!StaticPrefs::security_waict_enabled()) {
    return NS_OK;
  }

  if (aHeader.IsEmpty()) {
    return NS_OK;
  }

  RefPtr<IntegrityPolicyWAICT> policy = new IntegrityPolicyWAICT(aDocument);

  // We can't propagate the error here, because we would never flush
  // the console messages.
  if (NS_SUCCEEDED(policy->ParseHeader(aHeader))) {
    policy->FetchManifest();
  }

  policy.forget(aPolicy);
  return NS_OK;
}

nsresult IntegrityPolicyWAICT::ParseHeader(const nsACString& aHeader) {
  nsCOMPtr<nsISFVService> sfv = net::GetSFVService();
  if (!sfv) {
    return NS_ERROR_FAILURE;
  }

  nsCOMPtr<nsISFVDictionary> dict;
  nsresult rv = sfv->ParseDictionary(aHeader, getter_AddRefs(dict));
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseHeader: ParseDictionary failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderParseError", params);
    return rv;
  }

  auto destinationsResult =
      IntegrityPolicy::ParseDestinations(dict, /* aIsWAICT */ true);
  if (destinationsResult.isErr()) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseHeader: IntegrityPolicy::ParseDestinations failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader),
                                 u"destinations"_ns};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderFieldParseError", params);

    return destinationsResult.unwrapErr();
  }
  mDestinations = destinationsResult.unwrap();

  auto endpointsResult = IntegrityPolicy::ParseEndpoints(dict);
  if (endpointsResult.isErr()) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseHeader: IntegrityPolicy::ParseEndpoints failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader),
                                 u"endpoints"_ns};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderFieldParseError", params);

    return endpointsResult.unwrapErr();
  }
  mEndpoints = endpointsResult.unwrap();

  rv = waict::ParseMaxAge(dict, &mMaxAge);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseHeader: waict::ParseMaxAge failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader), u"max-age"_ns};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderFieldParseError", params);

    return rv;
  }

  rv = waict::ParseMode(dict, &mEnforce);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseHeader: waict::ParseMode failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader), u"mode"_ns};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderFieldParseError", params);

    return rv;
  }

  // Make sure this is the last step. We use the existence of the manifest URL
  // as a trigger to activate WAICT.
  rv = waict::ParseManifest(dict, mManifestURL);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "ParseHeader: waict::ParseManifest failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderManifestParseError", params);

    return rv;
  }

  return NS_OK;
}

static bool IsValidBase64(const nsACString& aBase64) {
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

static bool ValidateHashValue(const nsAString& aHash) {
  NS_ConvertUTF16toUTF8 hash(aHash);

  if (!IsValidBase64(hash)) {
    return false;
  }

  if (hash.Length() != 43 && hash.Length() != 44) {
    return false;
  }

  if (hash.Length() == 44 && hash[43] != '=') {
    return false;
  }

  if (hash.Length() == 43 && hash.Contains('=')) {
    return false;
  }

  return true;
}

IntegrityPolicyWAICT::ManifestValidationStatus
IntegrityPolicyWAICT::ValidateManifest(const nsACString& aManifestJSON,
                                       WAICTManifest& aOutManifest,
                                       IntegrityPolicyWAICT* aPolicy) {
  if (!aOutManifest.Init(NS_ConvertUTF8toUTF16(aManifestJSON))) {
    if (aPolicy) {
      aPolicy->ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                             "WAICTManifestJSONParseError", {});
    }
    return ManifestValidationStatus::InvalidJSON;
  }

  bool hasHashes = aOutManifest.mHashes.WasPassed() &&
                   !aOutManifest.mHashes.Value().Entries().IsEmpty();
  bool hasAnyHashes = aOutManifest.mAny_hashes.WasPassed() &&
                      !aOutManifest.mAny_hashes.Value().IsEmpty();

  if (!hasHashes && !hasAnyHashes) {
    return ManifestValidationStatus::MissingHashes;
  }

  if (hasHashes) {
    for (const auto& entry : aOutManifest.mHashes.Value().Entries()) {
      if (entry.mKey.IsEmpty() || !ValidateHashValue(entry.mValue)) {
        if (aPolicy) {
          nsTArray<nsString> params = {entry.mKey, entry.mValue};
          aPolicy->ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                                 "WAICTManifestInvalidHash", params);
        }

        return ManifestValidationStatus::InvalidHashFormat;
      }
    }
  }

  if (hasAnyHashes) {
    for (const auto& hash : aOutManifest.mAny_hashes.Value()) {
      if (!ValidateHashValue(hash)) {
        if (aPolicy) {
          nsTArray<nsString> params = {hash};
          aPolicy->ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                                 "WAICTManifestInvalidAnyHash", params);
        }

        return ManifestValidationStatus::InvalidHashFormat;
      }
    }
  }

  return ManifestValidationStatus::OK;
}

NS_IMETHODIMP IntegrityPolicyWAICT::OnStreamComplete(nsIStreamLoader* aLoader,
                                                     nsISupports* context,
                                                     nsresult aStatus,
                                                     uint32_t aDataLen,
                                                     const uint8_t* aData) {
  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "IntegrityPolicyWAICT::OnStreamComplete: dataLen = {}", aDataLen);

  if (NS_FAILED(aStatus)) {
    mManifestValid = false;
    mPromise->Resolve(true, __func__);
    return NS_OK;
  }

  nsDependentCSubstring data(reinterpret_cast<const char*>(aData), aDataLen);
  WAICTManifest manifest;
  ManifestValidationStatus status = ValidateManifest(data, manifest, this);
  if (status != ManifestValidationStatus::OK) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "Failed to validate WAICT manifest, error= {}",
                static_cast<uint8_t>(status));
    mManifestValid = false;
    mPromise->Resolve(true, __func__);
    return NS_OK;
  }

  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug, "Manifest validation successful");

  if (manifest.mHashes.WasPassed()) {
    MOZ_ASSERT(mHashes.IsEmpty());
    nsCOMPtr<nsIURI> uri;
    nsAutoCString spec;
    for (const auto& entry : manifest.mHashes.Value().Entries()) {
      if (NS_FAILED(NS_NewURI(getter_AddRefs(uri), entry.mKey, nullptr,
                              mDocument->GetDocumentURI())) ||
          NS_FAILED(uri->GetSpec(spec))) {
        nsTArray<nsString> params = {entry.mKey};
        ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                      "WAICTManifestInvalidURL", params);

        mPromise->Resolve(true, __func__);
        return NS_OK;
      }

      mHashes.InsertOrUpdate(spec, NS_ConvertUTF16toUTF8(entry.mValue));
    }
  }

  if (manifest.mAny_hashes.WasPassed()) {
    MOZ_ASSERT(mAnyHashes.IsEmpty());
    for (const auto& hash : manifest.mAny_hashes.Value()) {
      mAnyHashes.Insert(NS_ConvertUTF16toUTF8(hash));
    }
  }

  mManifestValid = true;
  mPromise->Resolve(true, __func__);
  return NS_OK;
}

void IntegrityPolicyWAICT::FetchManifest() {
  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "IntegrityPolicyWAICT::FetchManifest: mManifestURL={}",
              mManifestURL.get());

  mPromise = MakeRefPtr<WAICTManifestLoadedPromise::Private>(__func__);

  nsCOMPtr<nsIURI> uri;
  nsresult rv = NS_NewURI(getter_AddRefs(uri), mManifestURL, nullptr,
                          mDocument->GetDocumentURI());
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "Could not parse manifest URL: rv={}",
                static_cast<uint32_t>(rv));
    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(mManifestURL)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTManifestFetchURLParseError", params);
    mManifestValid = false;
    mPromise->Resolve(true, __func__);
    return;
  }

  nsCOMPtr<nsIPrincipal> principal = mDocument->NodePrincipal();
  nsCOMPtr<nsILoadGroup> loadGroup = mDocument->GetDocumentLoadGroup();
  nsCOMPtr<nsIStreamLoader> loader;
  rv = NS_NewStreamLoader(
      getter_AddRefs(loader), uri, this, principal,
      nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
      nsIContentPolicy::TYPE_OTHER, loadGroup);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "Could not fetch manifest URL: rv = {}",
                static_cast<uint32_t>(rv));
    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(mManifestURL)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTManifestFetchError", params);
    mManifestValid = false;
    mPromise->Resolve(true, __func__);
  }
}

void IntegrityPolicyWAICT::FlushConsoleMessages() {
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

void IntegrityPolicyWAICT::ReportMessage(uint32_t aErrorFlags,
                                         const nsACString& aCategory,
                                         const char* aMessageName,
                                         const nsTArray<nsString>& aParams) {
  if (mQueueUpMessages) {
    ConsoleMsgQueueElem& elem = *mConsoleMsgQueue.AppendElement();
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

}  // namespace mozilla::dom
