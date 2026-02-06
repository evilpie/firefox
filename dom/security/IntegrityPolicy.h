/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef IntegrityPolicy_h_
#define IntegrityPolicy_h_

#include "mozilla/EnumSet.h"
#include "mozilla/EnumTypeTraits.h"
#include "mozilla/Maybe.h"
#include "mozilla/MozPromise.h"
#include "mozilla/dom/WAICTManifestBinding.h"
#include "nsIContentPolicy.h"
#include "nsIIntegrityPolicy.h"
#include "nsIStreamLoader.h"
#include "nsTArray.h"

#define NS_INTEGRITYPOLICY_CONTRACTID "@mozilla.org/integritypolicy;1"

class nsISFVDictionary;
class nsILoadInfo;

namespace mozilla {
namespace ipc {
class IntegrityPolicyArgs;
}  // namespace ipc
namespace dom {

class Document;

class IntegrityPolicy : public nsIIntegrityPolicy,
                        public nsIStreamLoaderObserver {
 public:
  NS_DECL_ISUPPORTS
  NS_DECL_NSISERIALIZABLE
  NS_DECL_NSIINTEGRITYPOLICY
  NS_DECL_NSISTREAMLOADEROBSERVER

  IntegrityPolicy() = default;

  static nsresult ParseHeaders(const nsACString& aHeader,
                               const nsACString& aHeaderRO,
                               const nsACString& aWaict, nsIURI* aDocumentURI,
                               IntegrityPolicy** aPolicy,
                               Document* aDocument = nullptr);

  void FlushConsoleMessages();

  enum class SourceType : uint8_t { Inline };

  // Trimmed down version of dom::RequestDestination
  enum class DestinationType : uint8_t { Script, Style, Image };

  using Sources = EnumSet<SourceType>;
  using Destinations = EnumSet<DestinationType>;

  void PolicyContains(DestinationType aDestination, bool* aContains,
                      bool* aROContains) const;

  void Endpoints(nsTArray<nsCString>& aEnforcement,
                 nsTArray<nsCString>& aReportOnly) const;

  static Maybe<DestinationType> ContentTypeToDestinationType(
      nsContentPolicyType aType);

  static void ToArgs(const IntegrityPolicy* aPolicy,
                     mozilla::ipc::IntegrityPolicyArgs& aArgs);

  static void FromArgs(const mozilla::ipc::IntegrityPolicyArgs& aArgs,
                       IntegrityPolicy** aPolicy);

  void InitFromOther(IntegrityPolicy* aOther);

  static IntegrityPolicy* Cast(nsIIntegrityPolicy* aPolicy) {
    return static_cast<IntegrityPolicy*>(aPolicy);
  }

  static bool Equals(const IntegrityPolicy* aPolicy,
                     const IntegrityPolicy* aOtherPolicy);

  bool HasWaictFor(DestinationType aDestination);

  using WAICTManifestLoadedPromise =
      MozPromise<bool, bool, /* IsExclusive */ false>;
  RefPtr<WAICTManifestLoadedPromise> WaitForManifestLoad();

  bool CheckHash(nsIURI* aURI, const nsACString& aHash,
                 Document* aDocument = nullptr);

  enum class ManifestValidationStatus : uint8_t {
    OK,
    InvalidJSON,
    MissingVersion,
    InvalidVersion,
    MissingHashes,
    InvalidHashFormat
  };

  static ManifestValidationStatus ValidateManifest(
      const nsACString& aManifestJSON, WAICTManifest& aOutManifest);

 protected:
  virtual ~IntegrityPolicy();

 private:
  nsresult ParseWaict(nsIURI* aDocumentURI, const nsACString& aHeader,
                      Document* aDocument);
  void FetchWaictManifest();


  void ReportOrQueueMessage(uint32_t aErrorFlags, const nsACString& aCategory,
                            const char* aMessageName,
                            const nsTArray<nsString>& aParams);

  class Entry final {
   public:
    Entry(Sources aSources, Destinations aDestinations,
          nsTArray<nsCString>&& aEndpoints)
        : mSources(aSources),
          mDestinations(aDestinations),
          mEndpoints(std::move(aEndpoints)) {}

    Entry(const Entry& aOther)
        : mSources(aOther.mSources),
          mDestinations(aOther.mDestinations),
          mEndpoints(aOther.mEndpoints.Clone()) {}

    ~Entry() = default;

    static bool Equals(const Maybe<Entry>& aPolicy,
                       const Maybe<Entry>& aOtherPolicy);

    const Sources mSources;
    const Destinations mDestinations;
    const nsTArray<nsCString> mEndpoints;
  };

  Maybe<Entry> mEnforcement;
  Maybe<Entry> mReportOnly;

  nsCOMPtr<nsIURI> mDocumentURI;
  RefPtr<Document> mDocument;
  nsCString mWaictManifestURL;
  uint64_t mWaictMaxAge = 0;
  // XXX We should not use this directly.
  WAICTManifest mWaictManifest;
  Destinations mWaictDestinations;
  RefPtr<WAICTManifestLoadedPromise::Private> mWAICTPromise;

<<<<<<< HEAD
  struct IPConsoleMsgQueueElem {
    uint32_t mErrorFlags;
    nsCString mCategory;
    nsCString mMessageName;
    nsTArray<nsString> mParams;
  };

  bool mQueueUpMessages = true;
  nsTArray<IPConsoleMsgQueueElem> mConsoleMsgQueue;
=======
  // Hash tables for O(1) lookup performance with large manifests
  nsTHashMap<nsString, nsString> mHashesLookup;
  nsTHashSet<nsString> mAnyHashesLookup;
>>>>>>> 0911841d76d7 (Optimize manifest hash lookups with hash tables for O(1) performance)
};

}  // namespace dom

template <>
struct MaxEnumValue<dom::IntegrityPolicy::SourceType> {
  static constexpr unsigned int value =
      static_cast<unsigned int>(dom::IntegrityPolicy::SourceType::Inline);
};

template <>
struct MaxEnumValue<dom::IntegrityPolicy::DestinationType> {
  static constexpr unsigned int value =
      static_cast<unsigned int>(dom::IntegrityPolicy::DestinationType::Image);
};

}  // namespace mozilla

#endif /* IntegrityPolicy_h_ */
