/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "IntegrityPolicyWAICT.h"

#include "WAICTLog.h"
#include "WAICTUtils.h"
#include "mozilla/Logging.h"
#include "mozilla/dom/Document.h"
#include "mozilla/dom/WindowGlobalChild.h"
#include "mozilla/net/SFVService.h"
#include "nsContentUtils.h"
#include "nsIScriptError.h"

using namespace mozilla;

namespace mozilla::dom {

Result<IntegrityPolicy::Destinations, nsresult> ParseDestinations(
    nsISFVDictionary* aDict, bool aIsWAICT);

NS_IMPL_ISUPPORTS(IntegrityPolicyWAICT, nsIStreamLoaderObserver)

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
    nsIURI* aURI, const nsACString& aHash, Document* aDocument) {
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
    nsAutoCString path;
    nsresult rv = aURI->GetPathQueryRef(path);
    if (NS_SUCCEEDED(rv)) {
      if (auto hashValue = mHashes.Lookup(path)) {
        if (*hashValue != aHash) {
          MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                      "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Wrong hash for path "
                      "({} != {})",
                      *hashValue, nsCString(aHash));
          return false;
        }

        MOZ_LOG_FMT(gWaictLog, LogLevel::Info,
                    "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Correct hash "
                    "(path-based)");
        return true;
      }
    }
  }

  if (!mAnyHashes.IsEmpty()) {
    if (mAnyHashes.Contains(aHash)) {
      MOZ_LOG_FMT(gWaictLog, LogLevel::Info,
                  "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Hash found in any_hashes");
      return true;
    }
  }

  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug,
              "IntegrityPolicyWAICT::MaybeCheckResourceIntegrity: Hash not found in either "
              "lookup");
  return false;
}

/* static */
nsresult IntegrityPolicyWAICT::Create(Document* aDocument,
                                      const nsACString& aHeader,
                                      IntegrityPolicyWAICT** aPolicy) {
  NS_ENSURE_ARG_POINTER(aDocument);

  if (aHeader.IsEmpty()) {
    return NS_OK;
  }

  RefPtr<IntegrityPolicyWAICT> policy = new IntegrityPolicyWAICT(aDocument);

  MOZ_TRY(policy->ParseHeader(aHeader));
  policy->FetchManifest();

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
                "IntegrityPolicyWAICT::Initialize: ParseDictionary failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderParseError", params);
    return rv;
  }

  auto destinationsResult = ParseDestinations(dict, /* aIsWAICT */ true);
  if (destinationsResult.isErr()) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "IntegrityPolicyWAICT::Initialize: ParseDestinations failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderBlockedDestinationsParseError", params);

    return destinationsResult.unwrapErr();
  }

  mDestinations = destinationsResult.unwrap();

  rv = waict::ParseMaxAge(dict, &mMaxAge);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "IntegrityPolicyWAICT::Initialize: waict::ParseMaxAge failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderMaxAgeParseError", params);

    return rv;
  }

  rv = waict::ParseManifest(dict, mManifestURL);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(
        gWaictLog, LogLevel::Warning,
        "IntegrityPolicyWAICT::Initialize: waict::ParseManifest failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderManifestParseError", params);

    return rv;
  }

  rv = waict::ParseMode(dict, &mEnforce);
  if (NS_FAILED(rv)) {
    MOZ_LOG_FMT(gWaictLog, LogLevel::Warning,
                "IntegrityPolicyWAICT::Initialize: waict::ParseMode failed");

    nsTArray<nsString> params = {NS_ConvertUTF8toUTF16(aHeader)};
    ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                  "WAICTHeaderInvalidMode", params);

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

  if (aOutManifest.mVersion != 1) {
    if (aPolicy) {
      aPolicy->ReportMessage(nsIScriptError::errorFlag, "WAICT"_ns,
                             "WAICTManifestWrongVersion", {});
    }
    return ManifestValidationStatus::InvalidVersion;
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

  MOZ_LOG_FMT(gWaictLog, LogLevel::Debug, "Manifest validation successfull, version = {}", manifest.mVersion);

  if (mDocument && mDocument->GetDocumentURI()) {
    if (WindowGlobalChild* wgc = mDocument->GetWindowGlobalChild()) {
      wgc->SendSetSiteIntegrityProtected(
          WrapNotNull(mDocument->GetDocumentURI()), mMaxAge);
    }
  }

  if (manifest.mHashes.WasPassed()) {
    MOZ_ASSERT(mHashes.IsEmpty());
    for (const auto& entry : manifest.mHashes.Value().Entries()) {
      mHashes.InsertOrUpdate(NS_ConvertUTF16toUTF8(entry.mKey), NS_ConvertUTF16toUTF8(entry.mValue));
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

  // TODO: Proper principal/loadgroup etc.
  nsCOMPtr<nsIStreamLoader> loader;
  rv = NS_NewStreamLoader(
      getter_AddRefs(loader), uri, this, nsContentUtils::GetSystemPrincipal(),
      nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
      nsIContentPolicy::TYPE_OTHER);
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

bool IntegrityPolicyWAICT::Equals(const IntegrityPolicyWAICT* aWaict,
                                  const IntegrityPolicyWAICT* aOtherWaict) {
  if (aWaict == aOtherWaict) {
    return true;
  }

  if (!aWaict || !aOtherWaict) {
    return false;
  }

  if (aWaict->mManifestURL != aOtherWaict->mManifestURL) {
    return false;
  }

  if (aWaict->mMaxAge != aOtherWaict->mMaxAge) {
    return false;
  }

  if (aWaict->mDestinations != aOtherWaict->mDestinations) {
    return false;
  }

  return true;
}

}  // namespace mozilla::dom
