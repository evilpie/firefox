/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef IntegrityPolicyWAICT_h_
#define IntegrityPolicyWAICT_h_

#include "mozilla/MozPromise.h"
#include "mozilla/dom/IntegrityPolicy.h"
#include "mozilla/dom/WAICTManifestBinding.h"
#include "nsHashKeys.h"
#include "nsIStreamLoader.h"
#include "nsTHashMap.h"
#include "nsTHashSet.h"

namespace mozilla::dom {

class Document;

class IntegrityPolicyWAICT : public nsIStreamLoaderObserver {
 public:
  NS_DECL_ISUPPORTS
  NS_DECL_NSISTREAMLOADEROBSERVER

  static nsresult Create(Document* aDocument, const nsACString& aHeader,
                         IntegrityPolicyWAICT** aPolicy);

  void FlushConsoleMessages();

  bool ShouldHandle(IntegrityPolicy::DestinationType aDestination) {
    return !mManifestURL.IsEmpty() && mDestinations.contains(aDestination);
  }

  using WAICTManifestLoadedPromise =
      MozPromise<bool, bool, /* IsExclusive */ false>;
  RefPtr<WAICTManifestLoadedPromise> WaitForManifestLoad();

  bool MaybeCheckResourceIntegrity(
      nsIURI* aURI, IntegrityPolicy::DestinationType aDestination,
      const nsACString& aHash,

      Document* aDocument = nullptr);

  enum class ManifestValidationStatus : uint8_t {
    OK,
    InvalidJSON,
    MissingHashes,
    InvalidHashFormat
  };

  static ManifestValidationStatus ValidateManifest(
      const nsACString& aManifestJSON, WAICTManifest& aOutManifest,
      IntegrityPolicyWAICT* aPolicy = nullptr);

 protected:
  virtual ~IntegrityPolicyWAICT();

 private:
  explicit IntegrityPolicyWAICT(Document* aDocument);

  nsresult ParseHeader(const nsACString& aHeader);
  void FetchManifest();
  void ReportMessage(uint32_t aErrorFlags, const nsACString& aCategory,
                     const char* aMessageName,
                     const nsTArray<nsString>& aParams);


  RefPtr<Document> mDocument;

  nsCString mManifestURL;
  uint64_t mMaxAge = 0;
  IntegrityPolicy::Destinations mDestinations;
  nsTArray<nsCString> mEndpoints;

  RefPtr<WAICTManifestLoadedPromise::Private> mPromise;
  bool mEnforce = false;
  bool mManifestValid = false;
  // TODO(Bug 2017655): Use an nsURI as key.
  nsTHashMap<nsCString, nsCString> mHashes;
  nsTHashSet<nsCString> mAnyHashes;

  struct ConsoleMsgQueueElem {
    uint32_t mErrorFlags;
    nsCString mCategory;
    nsCString mMessageName;
    nsTArray<nsString> mParams;
  };

  bool mQueueUpMessages = true;
  nsTArray<ConsoleMsgQueueElem> mConsoleMsgQueue;
};

}  // namespace mozilla::dom

#endif /* IntegrityPolicyWAICT_h_ */
